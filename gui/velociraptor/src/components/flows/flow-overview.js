import React, { Fragment } from 'react';
import PropTypes from 'prop-types';
import VeloTimestamp from "../utils/time.js";
import VeloValueRenderer from "../utils/value.js";
import ArtifactLink from '../artifacts/artifacts-link.js';
import CardDeck from 'react-bootstrap/CardDeck';
import Card from 'react-bootstrap/Card';
import Dropdown from 'react-bootstrap/Dropdown';
import { FontAwesomeIcon } from '@fortawesome/react-fontawesome';
import { formatColumns } from "../core/table.js";
import { requestToParameters } from "./utils.js";
import Spinner from '../utils/spinner.js';
import Button from 'react-bootstrap/Button';
import ButtonGroup from 'react-bootstrap/ButtonGroup';
import Tooltip from 'react-bootstrap/Tooltip';
import OverlayTrigger from 'react-bootstrap/OverlayTrigger';
import T from '../i8n/i8n.js';
import BootstrapTable from 'react-bootstrap-table-next';
import _ from 'lodash';
import axios from 'axios';

import api from '../core/api-service.js';
import UserConfig from '../core/user.js';

const POLL_TIME = 5000;

export default class FlowOverview extends React.Component {
    static contextType = UserConfig;

    static propTypes = {
        flow: PropTypes.object,
    };

    componentDidMount = () => {
        this.source = axios.CancelToken.source();
        this.interval = setInterval(this.getDetailedFlow, POLL_TIME);
        this.getDetailedFlow();

        // Default state of the lock is set by the user's preferences.
        let lock_password = this.context.traits &&
            this.context.traits.default_password;
        this.setState({lock: lock_password});
    }

    componentWillUnmount() {
        this.source.cancel("unmounted");
        clearInterval(this.interval);
    }

    componentDidUpdate = (prevProps, prevState, rootNode) => {
        let old_flow_id = prevProps.flow && prevProps.flow.session_id;
        let new_flow_id = this.props.flow.session_id;

        if (old_flow_id !== new_flow_id) {
            this.setState({available_downloads: []});
            this.getDetailedFlow();
        }
    }

    prepareDownload = (download_type) => {
        let lock_password = "";
        if (this.state.lock) {
            lock_password = this.context.traits &&
                this.context.traits.default_password;
        }
        api.post("v1/CreateDownload", {
            flow_id: this.props.flow.session_id,
            client_id: this.props.flow.client_id,
            download_type: download_type || "",
            password: lock_password,
            expand_sparse: this.state.expand_sparse,
        }, this.source.token).then((response) => {
            this.getDetailedFlow();
        });
    };

    getDetailedFlow = () => {
        let flow_id = this.props.flow.session_id;
        let client_id = this.props.flow.client_id;

        if (_.isUndefined(flow_id) || _.isUndefined(client_id)) {
            return;
        }

        api.get("v1/GetFlowDetails", {
            flow_id: flow_id,
            client_id: client_id,
        }, this.source.token).then((response) => {
            let available_downloads = response.data.available_downloads &&
                response.data.available_downloads.files;
            this.setState({available_downloads: available_downloads || []});
        });
    }

    state = {
        loading: false,
        available_downloads: [],
        lock: false,
        expand_sparse: false,
    };

    render() {
        let flow = this.props.flow;
        let artifacts = flow && flow.request && flow.request.artifacts;

        if (!flow || !flow.session_id || !artifacts)  {
            if (this.state.loading) {
                return <Spinner loading={true}/>;
            }

            return <h5 className="no-content">{T("Please click a collection in the above table")}</h5>;
        }

        let parameters = requestToParameters(flow.request);

        let artifacts_with_results = flow.artifacts_with_results || [];
        let uploaded_files = flow.uploaded_files || [];
        let lock_password = this.context.traits &&
            this.context.traits.default_password;

        return (
            <>
            <CardDeck>
              <Card>
                <Card.Header>{T("Overview")}</Card.Header>
                <Card.Body>
                  <dl className="row">
                    <dt className="col-4">{T("Artifact Names")}</dt>
                    <dd className="col-8">
                      { _.map(artifacts, function(v, idx) {
                          return <ArtifactLink
                                   artifact={v}
                                   key={idx}>{v}</ArtifactLink>;
                      })}
                    </dd>

                    <dt className="col-4">{T("Flow ID")}</dt>
                    <dd className="col-8">  { flow.session_id } </dd>

                    <dt className="col-4">{T("Creator")}</dt>
                    <dd className="col-8"> { flow.request.creator } </dd>

                    <dt className="col-4">{T("Create Time")}</dt>
                    <dd className="col-8">
                      <VeloTimestamp usec={flow.create_time / 1000}/>
                    </dd>

                    <dt className="col-4">{T("Start Time")}</dt>
                    <dd className="col-8">
                      <VeloTimestamp usec={flow.start_time / 1000}/>
                    </dd>

                    <dt className="col-4">{T("Last Active")}</dt>
                    <dd className="col-8">
                      <VeloTimestamp usec={flow.active_time / 1000}/>
                    </dd>

                    <dt className="col-4">{T("Duration")}</dt>
                    <dd className="col-8">
                      { flow.execution_duration ?
                        ((flow.execution_duration)/1000000000).toFixed(2) +
                        " " + T("seconds") :
                        flow.state === "RUNNING" && T(" Running...")}
                    </dd>

                    <dt className="col-4">{T("State")}</dt>
                    <dd className="col-8">{ T(flow.state) }</dd>

                    { flow.state === "ERROR" &&
                      <Fragment>
                        <dt className="col-4">{T("Error")}</dt>
                        <dd className="col-8">{ flow.status }</dd>
                      </Fragment>
                    }

                    <dt className="col-4">{T("Ops/Sec")}</dt>
                    <dd className="col-8"> {flow.request.ops_per_second || T('Unlimited')} </dd>
                    <dt className="col-4">{T("CPU Limit")}</dt>
                    <dd className="col-8"> {flow.request.cpu_limit || T('Unlimited')} </dd>
                    <dt className="col-4">{T("IOPS Limit")}</dt>
                    <dd className="col-8"> {flow.request.iops_limit || T('Unlimited')} </dd>
                    <dt className="col-4">{T("Timeout")}</dt>
                    <dd className="col-8"> {flow.request.timeout || '600' } {T("seconds")}</dd>
                    <dt className="col-4">{T("Max Rows")}</dt>
                    <dd className="col-8"> {flow.request.max_rows || '1m'} {T("rows")}</dd>
                    <dt className="col-4">{T("Max Mb")}</dt>
                    <dd className="col-8"> { ((flow.request.max_upload_bytes || 1048576000)
                                              / 1024 / 1024).toFixed(2) } Mb</dd>
                    <br />
                  </dl>

                  <h5> Parameters </h5>
                  <dl className="row">
                    {_.map(artifacts, function(name, idx) {
                        return <React.Fragment key={idx}>
                                 <dt className="col-11">{name}</dt><dd className="col-1"/>
                                 {_.map(parameters[name], function(value, key) {
                                     if (value) {
                                         return <React.Fragment key={key}>
                                                  <dt className="col-4">{key}</dt>
                                                  <dd className="col-8">
                                                    <VeloValueRenderer value={value}/>
                                                  </dd>
                                                </React.Fragment>;
                                     };
                                     return <React.Fragment key={key}/>;
                                 })}
                               </React.Fragment>;
                    })}
                  </dl>
                </Card.Body>
              </Card>
              <Card>
                <Card.Header>{T("Results")}</Card.Header>
                <Card.Body>
                  <dl className="row">
                    <dt className="col-4">{T("Artifacts with Results")}</dt>
                    <dd className="col-8">
                      { _.map(artifacts_with_results, function(item, idx) {
                          return <VeloValueRenderer value={item} key={idx}/>;
                      })}
                    </dd>

                    <dt className="col-4">{T("Total Rows")}</dt>
                    <dd className="col-8">
                      { flow.total_collected_rows || 0 }
                    </dd>

                    <dt className="col-4">{T("Uploaded Bytes")}</dt>
                    <dd className="col-8">
                      { (flow.total_uploaded_bytes || 0) } / {
                        (flow.total_expected_uploaded_bytes || 0) }
                    </dd>

                    <dt className="col-4">{T("Files uploaded")}</dt>
                    <dd className="col-8">
                      {uploaded_files.length || flow.total_uploaded_files || 0 }
                    </dd>

                    <dt className="col-4">{T("Download Results")}</dt>
                    <dd className="col-8">
                      <ButtonGroup>
                        { lock_password ?
                          <Button
                            onClick={()=>this.setState({lock: !this.state.lock})}
                            variant="default">
                            {this.state.lock ?
                             <FontAwesomeIcon icon="lock"/> :
                             <FontAwesomeIcon icon="lock-open"/> }
                          </Button>
                          :
                          <OverlayTrigger
                            delay={{show: 250, hide: 400}}
                            overlay={
                                <Tooltip
                                  id='download-tooltip'>
                                  {T("Set a password in user preferences to lock the download file.")}
                                </Tooltip>
                            }>
                            <span className="d-inline-block">
                              <Button
                                style={{ pointerEvents: "none"}}
                                disabled={true}
                                variant="default">
                                <FontAwesomeIcon icon="lock-open"/>
                              </Button>
                            </span>
                          </OverlayTrigger>
                        }
                        {this.state.expand_sparse ?
                         <OverlayTrigger
                           delay={{show: 250, hide: 400}}
                           overlay={
                               <Tooltip
                                 id='expand-sparse'>
                                 {T("Sparse files will be expanded in export.")}
                               </Tooltip>
                           }>
                           <span className="d-inline-block">
                             <Button
                               onClick={()=>this.setState({expand_sparse: false})}
                               variant="default">
                               <FontAwesomeIcon icon="expand"/>
                             </Button>
                           </span>
                         </OverlayTrigger> :
                         <OverlayTrigger
                           delay={{show: 250, hide: 400}}
                           overlay={
                               <Tooltip
                                 id='expand-sparse'>
                                 {T("Sparse files will remain sparse in export.")}
                               </Tooltip>
                           }>
                           <span className="d-inline-block">
                             <Button
                               onClick={()=>this.setState({expand_sparse: !this.state.expand_sparse})}
                               variant="default">
                               <FontAwesomeIcon icon="compress"/>
                             </Button>
                           </span>
                         </OverlayTrigger>
                        }
                        <Dropdown>
                          <Dropdown.Toggle variant="default">
                            <FontAwesomeIcon icon="archive"/>
                          </Dropdown.Toggle>
                          <Dropdown.Menu>
                            <Dropdown.Item
                              onClick={()=>this.prepareDownload()}>
                              {T("Prepare Download")}
                            </Dropdown.Item>
                            <Dropdown.Item
                              onClick={()=>this.prepareDownload('report')}>
                              {T("Prepare Collection Report")}
                            </Dropdown.Item>
                          </Dropdown.Menu>
                        </Dropdown>
                      </ButtonGroup>
                    </dd>
                  </dl>
                  <dl>
                    <dt>{T("Available Downloads")}</dt>
                    <dd>
                      <BootstrapTable
                        keyField="name"
                        condensed
                        bootstrap4
                        hover
                        headerClasses="alert alert-secondary"
                        bodyClasses="fixed-table-body"
                        data={this.state.available_downloads}
                        columns={formatColumns(
                            [{dataField: "name", text: T("Name"), sort: true,
                              type: "download"},
                             {dataField: "size", text: T("Size (Mb)"), sort: true, type: "mb",
                              align: 'right'},
                             {dataField: "date", text: T("Date")}])}
                      />
                    </dd>
                  </dl>
                </Card.Body>
              </Card>
            </CardDeck>
            </>
        );
    }
};
