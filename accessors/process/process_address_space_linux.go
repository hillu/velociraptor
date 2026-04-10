//go:build linux
// +build linux

package process

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"unsafe"

	"www.velocidex.com/golang/velociraptor/accessors"
	"www.velocidex.com/golang/velociraptor/uploads"
)

type linuxProcessReader struct {
	pid     uint64
	fd      ReadAtCloser
	maps    []*mappedRegion
	pagemap map[int64]uint64
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
		const (
			PM_SOFT_DIRTY     = 1 << 55
			PM_MMAP_EXCLUSIVE = 1 << 56
			PM_UFFD_WP        = 1 << 57
			PM_FILE           = 1 << 61
			PM_SWAP           = 1 << 62
			PM_PRESENT        = 1 << 63
		)
		e := i + pagesize
		if e > len(buff) {
			e = len(buff)
		}
		entry := self.pagemap[(offset+int64(i))&int64(pagemask)]
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

func GetVads(pid uint64) ([]*uploads.Range, []*mappedRegion, map[int64]uint64, error) {
	maps_fd, err := os.Open(fmt.Sprintf("/proc/%d/maps", pid))
	if err != nil {
		return nil, nil, nil, err
	}

	defer maps_fd.Close()
	pagemap_fd, err := os.Open(fmt.Sprintf("/proc/%d/pagemap", pid))
	if err == nil {
		defer pagemap_fd.Close()
	}

	var ranges []*uploads.Range
	var maps []*mappedRegion
	pagemap := make(map[int64]uint64)

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
		return nil, nil, nil, err
	}

	if pagemap_fd != nil {
		for _, region := range maps {
			s := region.Start & int64(pagemask)
			e := (region.Start + region.Size) & int64(pagemask)

			for i := s; i <= e; i += int64(pagesize) {
				var buf [8]byte
				_, err := pagemap_fd.ReadAt(buf[:], 8*i/int64(pagesize))
				if err != nil {
					continue
				}
				pagemap[i] = *(*uint64)(unsafe.Pointer(&buf[0]))
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
