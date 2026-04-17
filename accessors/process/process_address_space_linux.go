//go:build linux
// +build linux

package process

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"unsafe"

	"www.velocidex.com/golang/velociraptor/accessors"
	"www.velocidex.com/golang/velociraptor/uploads"
)

const (
	PM_SOFT_DIRTY     = 1 << 55
	PM_MMAP_EXCLUSIVE = 1 << 56
	PM_UFFD_WP        = 1 << 57
	PM_FILE           = 1 << 61
	PM_SWAP           = 1 << 62
	PM_PRESENT        = 1 << 63
)

type pagemapRange struct {
	Start int64
	End   int64
	Flags uint64
}

func (self *pagemapRange) String() string {
	f := []byte("------")
	if self.Flags&PM_PRESENT != 0 {
		f[0] = 'P'
	}
	if self.Flags&PM_SWAP != 0 {
		f[1] = 'S'
	}
	if self.Flags&PM_FILE != 0 {
		f[2] = 'F'
	}
	if self.Flags&PM_UFFD_WP != 0 {
		f[3] = 'U'
	}
	if self.Flags&PM_MMAP_EXCLUSIVE != 0 {
		f[4] = 'X'
	}
	if self.Flags&PM_SOFT_DIRTY != 0 {
		f[5] = 'D'
	}
	return fmt.Sprintf("%08x-%08x %s", self.Start, self.End, string(f))
}

type pagemapRanges struct {
	ranges []pagemapRange
}

func (self *pagemapRanges) append(r pagemapRange) {
	// Assumption: pagemapRanges is always sorted by startAddress and
	// ranges are only appended, never inserted in the middle. This
	// holds true as long as /proc/$PID/maps is ordered in this way.
	if n := len(self.ranges); n > 0 {
		last := &self.ranges[n-1]
		if last.End == r.Start && last.Flags == r.Flags {
			last.End = r.End
			return
		}
	}
	self.ranges = append(self.ranges, r)
}

func (self *pagemapRanges) lookup(addr int64) uint64 {
	i, found := sort.Find(len(self.ranges), func(i int) int {
		switch {
		case addr < self.ranges[i].Start:
			return -1
		case addr >= self.ranges[i].End:
			return 1
		default:
			return 0
		}
	})
	if found {
		return self.ranges[i].Flags
	}
	return 0
}

type linuxProcessReader struct {
	pid     uint64
	fd      ReadAtCloser
	maps    []*mappedRegion
	pagemap pagemapRanges
}

func (self *linuxProcessReader) openMappedFile(mapping *mappedRegion) *os.File {
	if mapping.Deleted {
		return nil
	}
	file, err := os.Open(fmt.Sprintf("/proc/%d/root%s", self.pid, mapping.FilePath))
	if err != nil {
		return nil
	}
	fi, err := file.Stat()
	if err != nil {
		file.Close()
		return nil
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		file.Close()
		return nil
	}
	if st.Dev != mapping.Device || st.Ino != mapping.Inode {
		file.Close()
		return nil
	}
	return file
}

func (self *linuxProcessReader) ReadAt(buff []byte, offset int64) (int, error) {
	var file *os.File
	var fileBacked = false
	fileOffset := int64(0)

	for _, mapping := range self.maps {
		if offset >= mapping.Start && offset <= mapping.Start+mapping.Size &&
			offset+int64(len(buff)) <= mapping.Start+mapping.Size {
			if strings.HasPrefix(mapping.FilePath, "/") {
				fileBacked = true
			}
			if mapping.Device == 0 && mapping.Inode == 0 {
				break
			}
			if file = self.openMappedFile(mapping); file != nil {
				fileOffset = mapping.FileOffset + (offset - mapping.Start)
				defer file.Close()
			}
			break
		}
	}

	for i := range buff {
		buff[i] = 0
	}
	count := 0
	for i := 0; i < len(buff); i += pagesize {
		e := i + pagesize
		if e > len(buff) {
			e = len(buff)
		}
		entry := self.pagemap.lookup((offset + int64(i)) & int64(pagemask))
		if !fileBacked && entry&(PM_SWAP|PM_PRESENT|PM_FILE) == 0 {
			// page is not present in target process; return zeros
			count += e - i
			continue
		}
		if fileBacked && file != nil && entry&(PM_FILE) == PM_FILE {
			// page is present in backing file.
			n, err := file.ReadAt(buff[i:e], fileOffset+int64(i))
			if err == nil {
				count += n
				continue
			}
		}
		// fall back to reading through /proc/$PID/mem
		n, err := self.fd.ReadAt(buff[i:e], offset+int64(i))
		count += n
		if err != nil {
			return count, err
		}
	}
	return count, nil
}

func (self *linuxProcessReader) Close() error {
	return self.fd.Close()
}

func (self *ProcessAccessor) OpenWithOSPath(
	path *accessors.OSPath) (accessors.ReadSeekCloser, error) {
	if len(path.Components) == 0 {
		return nil, errors.New("Unable to list all processes, use the pslist() plugin.")
	}

	pid, err := strconv.ParseUint(path.Components[0], 0, 64)
	if err != nil {
		return nil, errors.New("First directory path must be a process.")
	}

	// Open the device file for the process
	fd, err := os.Open(fmt.Sprintf("/proc/%d/mem", pid))
	if err != nil {
		return nil, err
	}

	// Open the process and enumerate its ranges
	ranges, maps, pagemap, err := GetVads(pid)
	if err != nil {
		return nil, err
	}

	result := &ProcessReader{
		pid:    pid,
		handle: &linuxProcessReader{pid, fd, maps, pagemap},
	}

	for _, r := range ranges {
		result.ranges = append(result.ranges, r)
	}

	return result, nil
}

var (
	maps_regexp = regexp.MustCompile(`(?P<Start>^[^-]+)-(?P<End>[^\s]+)\s+(?P<Perm>[^\s]+)\s+(?P<Offset>[^\s]+)\s+(?P<Dev>[^\s]+)\s+(?P<Inode>[^\s]+)\s+(?P<Filename>.+?)(?P<Deleted> \(deleted\))?$`)

	pagesize = syscall.Getpagesize()
	pagemask = ^(pagesize - 1)
)

type mappedRegion struct {
	Start      int64
	Size       int64
	FileOffset int64
	FilePath   string
	Device     uint64
	Inode      uint64
	Deleted    bool
}

func GetVads(pid uint64) ([]*uploads.Range, []*mappedRegion, pagemapRanges, error) {
	maps_fd, err := os.Open(fmt.Sprintf("/proc/%d/maps", pid))
	if err != nil {
		return nil, nil, pagemapRanges{}, err
	}

	defer maps_fd.Close()
	pagemap_fd, err := os.Open(fmt.Sprintf("/proc/%d/pagemap", pid))
	if err == nil {
		defer pagemap_fd.Close()
	}

	var ranges []*uploads.Range
	var maps []*mappedRegion
	var pagemap pagemapRanges

	scanner := bufio.NewScanner(maps_fd)
	for scanner.Scan() {
		hits := maps_regexp.FindStringSubmatch(scanner.Text())
		if len(hits) > 0 {
			protection := hits[3]
			// Only include readable ranges.
			if len(protection) < 2 || protection[0] != 'r' {
				continue
			}

			start, err := strconv.ParseInt(hits[1], 16, 64)
			if err != nil {
				continue
			}

			end, err := strconv.ParseInt(hits[2], 16, 64)
			if err != nil {
				continue
			}

			offset, err := strconv.ParseInt(hits[4], 16, 64)
			if err != nil {
				continue
			}

			dev := strings.Split(hits[5], ":")
			if len(dev) < 2 {
				dev = append(dev, "0")
			}
			dev_maj, _ := strconv.ParseUint(dev[0], 16, 64)
			dev_min, _ := strconv.ParseUint(dev[1], 16, 64)

			inode, err := strconv.ParseUint(hits[6], 10, 64)
			if err != nil {
				continue
			}

			filepath := hits[7]
			deleted := hits[8] != ""

			maps = append(maps, &mappedRegion{
				Start:      start,
				Size:       end - start,
				FileOffset: offset,
				Device:     makedev(dev_maj, dev_min),
				Inode:      inode,
				FilePath:   filepath,
				Deleted:    deleted,
			})

			// We can not read kernel memory
			if start < 0 || end < 0 {
				continue
			}

			ranges = append(ranges, &uploads.Range{
				Offset: start, Length: end - start,
			})
		}
	}

	err = scanner.Err()
	if err != nil {
		return nil, nil, pagemapRanges{}, err
	}

	if pagemap_fd != nil {
		for _, region := range maps {
			for start := region.Start & int64(pagemask); start <= (region.Start+region.Size)&int64(pagemask); start += int64(pagesize) {
				var buf [8]byte
				_, err := pagemap_fd.ReadAt(buf[:], 8*start/int64(pagesize))
				if err != nil {
					continue
				}

				flags := *(*uint64)(unsafe.Pointer(&buf[0]))
				pagemap.append(pagemapRange{start, start + int64(pagesize), flags})
			}
		}
	}

	return ranges, maps, pagemap, nil
}

// makedev macro, taken from sysmacros.h
func makedev(maj, min uint64) uint64 {
	return ((maj & 0xfffff000) << 32) |
		((maj & 0x00000fff) << 8) |
		((min & 0xffffff00) << 12) |
		(min & 0x000000ff)
}
