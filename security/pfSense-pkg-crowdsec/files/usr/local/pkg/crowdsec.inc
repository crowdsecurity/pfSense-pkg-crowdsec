<?php
/*
 * crowdsec.inc
 *
 * Copyright (c) 2020-2023 Crowdsec
 * All rights reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

require_once("config.inc");
require_once("globals.inc");
require_once("config.lib.inc");
require_once("filter.inc");
require_once("/usr/local/pkg/crowdsec/vendor/autoload.php");

use Symfony\Component\Yaml\Yaml;
use Symfony\Component\Yaml\Exception\ParseException;
use Symfony\Component\Yaml\Exception\DumpException;

define('CROWDSEC_LAPI_CONF', '/usr/local/etc/crowdsec/local_api_credentials.yaml');
define('CROWDSEC_AGENT_CONF', '/usr/local/etc/crowdsec/config.yaml');
define('CROWDSEC_FIREWALL_CONF', '/usr/local/etc/crowdsec/bouncers/crowdsec-firewall-bouncer.yaml');

$g['disablehelpicon'] = true;

global $crowdsec_aliases;
$crowdsec_aliases = array(
    array(
        'name' => 'crowdsec_blacklists',
        'address' => "",
        'descr' => 'Crowdsec blacklists IPv4 (DO NOT EDIT)',
        'type' => 'host',
        'detail' => ''
    ),
    array(
        'name' => 'crowdsec6_blacklists',
        'address' => "",
        'descr' => 'Crowdsec blacklists IPv6 (DO NOT EDIT)',
        'type' => 'host',
        'detail' => ''
    ),

);

/**
 * custom_php_validation_command hook (setting edition before submit)
 *
 * @param $post
 * @param $input_errors
 * @return void
 */
function crowdsec_validate_form($post, &$input_errors)
{
    if (!empty($post['lapi_port'])) {
        $lapi_port = $post['lapi_port'];
        if (!is_numeric($lapi_port)) {
            $input_errors[] = 'LAPI port must be a numeric value.';
        }
    }
    if (!empty($post['metrics_port'])) {
        $metrics_port = $post['metrics_port'];
        if (!is_numeric($metrics_port)) {
            $input_errors[] = 'Metrics port (crowdsec) must be a numeric value.';
        }
    }
    if (!empty($post['metrics_firewall_port'])) {
        $metrics_firewall_port = $post['metrics_firewall_port'];
        if (!is_numeric($metrics_firewall_port)) {
            $input_errors[] = 'Metrics port (firewall bouncer) must be a numeric value.';
        }
    }
    // Use external LAPI
    if (!empty($post['lapi_is_remote'])) {
        if (empty($post['agent_user'])) {
            $input_errors[] = 'Agent user is required for external LAPI usage.';
        }
        if (empty($post['agent_password'])) {
            $input_errors[] = 'Agent password is required for external LAPI usage.';
        }
        if (empty($post['fw_bouncer_api_key'])) {
            $input_errors[] = 'Firewall bouncer API key is required for external LAPI usage.';
        }
    }
}

/**
 * custom_php_install_command hook (package installation)
 *
 * @return void
 */
function crowdsec_install()
{
    // UPDATE pfSense ALIAS TABLES
    global $crowdsec_aliases;
    parse_config(true);
    config_init_path(implode('/', ['aliases']));
    $exist_aliases = config_get_path('aliases/alias', []);
    $exist_aliases_names = array_column($exist_aliases, 'name');
    $final_aliases = $exist_aliases;
    // Add Crowdsec alias if not exist
    foreach ($crowdsec_aliases as $crowdsec_alias) {
        if (!in_array($crowdsec_alias['name'], $exist_aliases_names)) {
            $final_aliases[] = $crowdsec_alias;
        }
    }
    // Update config.xml, if changes required
    if ($exist_aliases !== $final_aliases) {
        config_set_path('aliases/alias', $final_aliases);
        write_config('pfsense_crowdsec: saving Aliases');
    }
    unset($final_aliases, $exist_aliases);
    // Update rules
    crowdsec_generate_rules('filter');
    filter_configure();
    // Add aliases name in firewall bouncer configuration
    $fw_conf = [];
    try {
        $fw_conf = Yaml::parse(file_get_contents(CROWDSEC_FIREWALL_CONF));
    } catch (ParseException $exception) {
        syslog(LOG_ERR, 'Unable to parse ' . CROWDSEC_FIREWALL_CONF . ': ' . $exception->getMessage());
    }
    if (!empty($fw_conf)) {
        $fw_conf['blacklists_ipv4'] = $crowdsec_aliases[0]['name'];
        $fw_conf['blacklists_ipv6'] = $crowdsec_aliases[1]['name'];
        try {
            $yaml = Yaml::dump($fw_conf, 4);
            file_put_contents(CROWDSEC_FIREWALL_CONF, $yaml);
        } catch (DumpException $exception) {
            syslog(LOG_ERR, 'Unable to dump ' . CROWDSEC_FIREWALL_CONF . ': ' . $exception->getMessage());
        }
    }
}

/**
 * Find aliases array index
 * @param $name
 * @return int|string
 */
function get_alias_index($name)
{
    config_init_path(implode('/', ['aliases']));
    foreach (config_get_path('aliases/alias', []) as $idx => $alias) {
        if ($alias['name'] == $name) {
            return $idx;
        }
    }

    return -1;
}

/**
 * custom_php_pre_deinstall_command hook (package deinstallation)
 *
 * @return void
 */
function crowdsec_deinstall()
{
    // Delete aliases
    global $crowdsec_aliases;
    $delete_flag = false;
    parse_config(true);
    foreach ($crowdsec_aliases as $crowdsec_alias) {
        $crowdsec_index = get_alias_index($crowdsec_alias['name']);
        if ($crowdsec_index !== -1) {
            config_del_path("aliases/alias/{$crowdsec_index}");
            $delete_flag = true;
        }
    }
    if ($delete_flag) {
        write_config('pfsense_crowdsec: deleting aliases');
    }
    // Delete rules
    crowdsec_generate_rules('deinstall');
    filter_configure();
}

/**
 * custom_php_resync_config_command hook (install, setting edition, ...)
 *
 * @return void
 */
function crowdsec_resync_config()
{
    $cf = config_get_path('installedpackages/crowdsec/config/0', []);
    $candidate_log_dir = '/var/log/crowdsec/';
    // Handle crowdsec service start
    if (!empty($cf['enable_agent'])) {
        // Enable service
        mwexec('service crowdsec enable');
        // Modify LAPI settings (update local_api_credentials.yaml)
        $lapi_conf = [];
        $update_lapi_flag = false;
        try {
            $lapi_conf = Yaml::parse(file_get_contents(CROWDSEC_LAPI_CONF));
        } catch (ParseException $exception) {
            syslog(LOG_ERR, 'Unable to parse ' . CROWDSEC_LAPI_CONF . ': ' . $exception->getMessage());
        }
        if (!empty($lapi_conf)) {
            if (!empty($cf['lapi_port']) && !empty($cf['lapi_host'])) {
                $lapi_url = $lapi_conf['url'] ?? '';
                $candidate_url = 'http://' . $cf['lapi_host'] . ':' . $cf['lapi_port'];
                if ($candidate_url !== $lapi_url) {
                    $lapi_conf['url'] = $candidate_url;
                    $update_lapi_flag = true;
                }
            }
            if ($update_lapi_flag) {
                try {
                    $yaml = Yaml::dump($lapi_conf, 4);
                    file_put_contents(CROWDSEC_LAPI_CONF, $yaml);
                } catch (DumpException $exception) {
                    syslog(LOG_ERR, 'Unable to dump ' . CROWDSEC_LAPI_CONF . ': ' . $exception->getMessage());
                }
            }
        }

        // Modify AGENT settings (update /usr/local/etc/crowdsec/config.yaml)
        $agent_conf = [];
        $update_agent_flag = false;
        try {
            $agent_conf = Yaml::parse(file_get_contents(CROWDSEC_AGENT_CONF));
        } catch (ParseException $exception) {
            syslog(LOG_ERR, 'Unable to parse ' . CROWDSEC_AGENT_CONF . ': ' . $exception->getMessage());
        }
        if(!empty($agent_conf)){
            if (!empty($cf['lapi_port']) && !empty($cf['lapi_host'])) {
                $agent_url = $agent_conf['api']['server']['listen_uri'] ?? '';
                $candidate_url = $cf['lapi_host'] . ':' . $cf['lapi_port'];
                if ($candidate_url !== $agent_url) {
                    $agent_conf['api']['server']['listen_uri'] = $candidate_url;
                    $update_agent_flag = true;
                }
            }
            if (!empty($cf['agent_log_level'])) {
                $agent_log_level = $agent_conf['common']['log_level'] ?? 'info';
                $candidate_level = $cf['agent_log_level'];
                if ($candidate_level !== $agent_log_level) {
                    $agent_conf['common']['log_level'] = $candidate_level;
                    $update_agent_flag = true;
                }
            }
            if (!empty($cf['metrics_port'])) {
                $agent_metrics_port = $agent_conf['prometheus']['listen_port'] ?? 6060;
                $candidate_port = $cf['metrics_port'];
                if ($candidate_port !== $agent_metrics_port) {
                    $agent_conf['prometheus']['listen_port'] = (int)$candidate_port;
                    $update_agent_flag = true;
                }
            }
            $agent_log_dir = $agent_conf['common']['log_dir'] ?? $candidate_log_dir;
            if ($candidate_log_dir !== $agent_log_dir) {
                $agent_conf['common']['log_dir'] = $candidate_log_dir;
                $update_agent_flag = true;
            }
            if ($update_agent_flag) {
                try {
                    $yaml = Yaml::dump($agent_conf, 4);
                    file_put_contents(CROWDSEC_AGENT_CONF, $yaml);
                } catch (DumpException $exception) {
                    syslog(LOG_ERR, 'Unable to dump ' . CROWDSEC_AGENT_CONF . ': ' . $exception->getMessage());
                }
            }
        }
        // Start service
        mwexec('service crowdsec restart');
    } else {
        // Disable service
        mwexec('service crowdsec stop');
        mwexec('service crowdsec disable');
    }

    // Handle crowdsec_firewall service start
    if (!empty($cf['enable_fw_bouncer'])) {
        // Enable service
        mwexec('service crowdsec_firewall enable');
        // Modify Firewall bouncer settings (update /usr/local/etc/crowdsec/bouncers/crowdsec-firewall-bouncer.yaml)
        $fw_conf = [];
        $update_fw_flag = false;
        try {
            $fw_conf = Yaml::parse(file_get_contents(CROWDSEC_FIREWALL_CONF));
        } catch (ParseException $exception) {
            syslog(LOG_ERR, 'Unable to parse ' . CROWDSEC_FIREWALL_CONF . ': ' . $exception->getMessage());
        }
        if(!empty($fw_conf)){
            if (!empty($cf['lapi_port']) && !empty($cf['lapi_host'])) {
                $fw_url = $fw_conf['api_url'] ?? '';
                $candidate_url = 'http://' . $cf['lapi_host'] . ':' . $cf['lapi_port'] . '/';
                if ($candidate_url !== $fw_url) {
                    $fw_conf['api_url'] = $candidate_url;
                    $update_fw_flag = true;
                }
            }
            if (!empty($cf['firewall_bouncer_log_level'])) {
                $fw_log_level = $fw_conf['log_level'] ?? '';
                $candidate_level = $cf['firewall_bouncer_log_level'];
                if ($candidate_level !== $fw_log_level) {
                    $fw_conf['log_level'] = $candidate_level;
                    $update_fw_flag = true;
                }
            }
            if (!empty($cf['metrics_firewall_port'])) {
                $fw_metrics_port = $fw_conf['prometheus']['listen_port'] ?? 6060;
                $candidate_port = $cf['metrics_firewall_port'];
                if ($candidate_port !== $fw_metrics_port) {
                    $fw_conf['prometheus']['listen_port'] = (int)$candidate_port;
                    $update_fw_flag = true;
                }
            }
            $fw_log_dir = $fw_conf['log_dir'] ?? $candidate_log_dir;
            if ($candidate_log_dir !== $fw_log_dir) {
                $fw_conf['log_dir'] = $candidate_log_dir;
                $update_fw_flag = true;
            }
            if ($update_fw_flag) {
                try {
                    $yaml = Yaml::dump($fw_conf, 4);
                    file_put_contents(CROWDSEC_FIREWALL_CONF, $yaml);
                } catch (DumpException $exception) {
                    syslog(LOG_ERR, 'Unable to dump ' . CROWDSEC_FIREWALL_CONF . ': ' . $exception->getMessage());
                }
            }
        }
        // Start service
        mwexec('service crowdsec_firewall restart');
    } else {
        // Disable service
        mwexec('service crowdsec_firewall stop');
        mwexec('service crowdsec_firewall disable');
    }
}

/**
 * filter_rules_needed hook (install, setting edition, ...)
 *
 * @param $type
 * @return string
 */
function crowdsec_generate_rules($type)
{
    $rules = "";
    switch ($type) {
        case 'filter':
            global $config;
            $cf = $config['installedpackages']['crowdsec']['config'][0] ?? array();

            if (!empty($cf['enable_block_v4'])) {
                $rules .= "block drop";
                $direction = !empty($cf['block_v4_direction']) && $cf['block_v4_direction'] !== 'any' ?
                    $cf['block_v4_direction'] : '';
                $log = !empty($cf['block_v4_log']) ? "log" : '';
                $tag = !empty($cf['block_v4_tag']) ? "tag " . $cf['block_v4_tag'] : '';

                $rules .= ' ' . $direction . ' ' . $log .
                          ' quick inet from <crowdsec_blacklists> to any label "CrowdSec IPv4"';
                if (!empty($tag)) {
                    $rules .= ' ' . $tag;
                }
                $rules .= "\n";
            }
            if (!empty($cf['enable_block_v6'])) {
                $rules .= "block drop";
                $direction = !empty($cf['block_v6_direction']) && $cf['block_v6_direction'] !== 'any' ?
                    $cf['block_v6_direction'] : '';
                $log = !empty($cf['block_v6_log']) ? "log" : '';
                $tag = !empty($cf['block_v6_tag']) ? "tag " . $cf['block_v6_tag'] : '';

                $rules .= ' ' . $direction . ' ' . $log .
                          ' quick inet6 from <crowdsec6_blacklists> to any label "CrowdSec IPv6"';
                if (!empty($tag)) {
                    $rules .= ' ' . $tag;
                }
                $rules .= "\n";
            }
            break;
        default:
            break;
    }

    if (!empty($rules)) {
        syslog(LOG_INFO, "CrowdSec rules:\n $rules");
    }

    return $rules;
}

