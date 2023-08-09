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
define('CROWDSEC_SETTINGS_NOTICE', '/usr/local/www/crowdsec/settings-notice.txt');
define('CROWDSEC_PFSENSE_COLLECTION', '/usr/local/etc/crowdsec/collections/pfsense.yaml');

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
    // Prepare rc.conf.d variables
    mwexec('mkdir -p /usr/local/etc/rc.conf.d');
    mwexec('sysrc -f /usr/local/etc/rc.conf.d/crowdsec crowdsec_machine_name=pfsense');
    mwexec('sysrc -f /usr/local/etc/rc.conf.d/crowdsec_firewall crowdsec_firewall_name=pfsense-firewall');
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

function get_yaml_content($filepath)
{
    $result = [];
    try {
        $result = Yaml::parse(file_get_contents($filepath));
    } catch (ParseException $exception) {
        syslog(LOG_ERR, 'Unable to parse ' . $filepath . ': ' . $exception->getMessage());
    }

    return $result;
}

function set_yaml_content($content, $filepath)
{
    try {
        $yaml = Yaml::dump($content, 4);
        file_put_contents($filepath, $yaml);
    } catch (DumpException $exception) {
        syslog(LOG_ERR, 'Unable to dump ' . $filepath . ': ' . $exception->getMessage());
    }
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
    $candidate_log_max_size = 999999;
    $candidate_db_wal = true;
    // Handle remote LAPI ON
    if (!empty($cf['lapi_is_remote'])) {
        // Modify AGENT settings (update /usr/local/etc/crowdsec/config.yaml)
        $agent_conf = get_yaml_content(CROWDSEC_AGENT_CONF);
        $update_agent_flag = false;
        if (!empty($agent_conf)) {
            $agent_conf['api']['server']['enable'] = false;
            $update_agent_flag = true;
        }
        if ($update_agent_flag) {
            set_yaml_content($agent_conf, CROWDSEC_AGENT_CONF);
        }
        // Modify LAPI settings (update local_api_credentials.yaml)
        $lapi_conf = get_yaml_content(CROWDSEC_LAPI_CONF);
        $update_lapi_flag = false;
        if (!empty($lapi_conf)) {
            if (!empty($cf['agent_user']) && !empty($cf['agent_password'])) {
                $lapi_login = $lapi_conf['login'] ?? '';
                $candidate_login = $cf['agent_user'];
                if ($candidate_login !== $lapi_login) {
                    $lapi_conf['login'] = $candidate_login;
                    $update_lapi_flag = true;
                }
                $lapi_password = $lapi_conf['password'] ?? '';
                $candidate_password = $cf['agent_password'];
                if ($candidate_password !== $lapi_password) {
                    $lapi_conf['password'] = $candidate_password;
                    $update_lapi_flag = true;
                }
            }
            if ($update_lapi_flag) {
                set_yaml_content($lapi_conf, CROWDSEC_LAPI_CONF);
            }
        }
        // Modify Firewall bouncer settings (update /usr/local/etc/crowdsec/bouncers/crowdsec-firewall-bouncer.yaml)
        $fw_conf = get_yaml_content(CROWDSEC_FIREWALL_CONF);
        $update_fw_flag = false;
        if (!empty($fw_conf)) {
            if (!empty($cf['fw_bouncer_api_key'])) {
                $fw_api_key = $fw_conf['api_key'] ?? '';
                $candidate_key = $cf['fw_bouncer_api_key'];
                if ($candidate_key !== $fw_api_key) {
                    $fw_conf['api_key'] = $candidate_key;
                    $update_fw_flag = true;
                }
            }
            if ($update_fw_flag) {
                set_yaml_content($fw_conf, CROWDSEC_FIREWALL_CONF);
            }
        }
        mwexec('service crowdsec enable');
        mwexec('service crowdsec start');
        mwexec('service crowdsec_firewall enable');
        mwexec('service crowdsec_firewall start');
    } else { // Handle remote LAPI OFF
        // Modify AGENT settings (update /usr/local/etc/crowdsec/config.yaml)
        $agent_conf = get_yaml_content(CROWDSEC_AGENT_CONF);
        $update_agent_flag = false;
        if (!empty($agent_conf)) {
            $agent_conf['api']['server']['enable'] = true;
            $update_agent_flag = true;
        }
        if ($update_agent_flag) {
            set_yaml_content($agent_conf, CROWDSEC_AGENT_CONF);
        }
        // Modify Firewall bouncer settings (update /usr/local/etc/crowdsec/bouncers/crowdsec-firewall-bouncer.yaml)
        $fw_conf = get_yaml_content(CROWDSEC_FIREWALL_CONF);
        $update_fw_flag = false;
        if (!empty($fw_conf)) {
            $fw_api_key = $fw_conf['api_key'] ?? '';
            $candidate_key = '${API_KEY}';
            if ($candidate_key !== $fw_api_key) {
                $fw_conf['api_key'] = $candidate_key;
                $update_fw_flag = true;
            }
            if ($update_fw_flag) {
                set_yaml_content($fw_conf, CROWDSEC_FIREWALL_CONF);
            }
        }
        mwexec('cscli bouncers delete pfsense-firewall');
        mwexec('cscli machines delete pfense');
        mwexec('service crowdsec enable');
        mwexec('service crowdsec start');
        mwexec('service crowdsec_firewall enable');
        mwexec('service crowdsec_firewall start');
    }

    // Handle crowdsec service start
    if (!empty($cf['enable_agent'])) {
        // Enable service
        mwexec('service crowdsec enable');
        // Modify LAPI settings (update local_api_credentials.yaml)
        $lapi_conf = get_yaml_content(CROWDSEC_LAPI_CONF);
        $update_lapi_flag = false;
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
                set_yaml_content($lapi_conf, CROWDSEC_LAPI_CONF);
            }
        }

        // Modify AGENT settings (update /usr/local/etc/crowdsec/config.yaml)
        $agent_conf = get_yaml_content(CROWDSEC_AGENT_CONF);
        $update_agent_flag = false;
        if (!empty($agent_conf)) {
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
            $agent_log_max_size = $agent_conf['common']['log_max_size'] ?? $candidate_log_max_size;
            if ($candidate_log_max_size !== $agent_log_max_size) {
                $agent_conf['common']['log_max_size'] = $candidate_log_max_size;
                $update_agent_flag = true;
            }
            $agent_db_wal = $agent_conf['db_config']['use_wal'] ?? '';
            if ($candidate_db_wal !== $agent_db_wal) {
                $agent_conf['db_config']['use_wal'] = $candidate_db_wal;
                $update_agent_flag = true;
            }
            if ($update_agent_flag) {
                set_yaml_content($agent_conf, CROWDSEC_AGENT_CONF);
            }
        }
        // Start service
        mwexec('service crowdsec start');
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
        $fw_conf = get_yaml_content(CROWDSEC_FIREWALL_CONF);
        $update_fw_flag = false;
        if (!empty($fw_conf)) {
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
            $fw_log_max_size = $fw_conf['log_max_size'] ?? $candidate_log_max_size;
            if ($candidate_log_max_size !== $fw_log_max_size) {
                $fw_conf['log_max_size'] = $candidate_log_max_size;
                $update_fw_flag = true;
            }
            if ($update_fw_flag) {
                set_yaml_content($fw_conf, CROWDSEC_FIREWALL_CONF);
            }
        }
        // Start service
        mwexec('service crowdsec_firewall start');
    } else {
        // Disable service
        mwexec('service crowdsec_firewall stop');
        mwexec('service crowdsec_firewall disable');
    }
    if ($_POST) {
        $notice_content = 'Settings saved.' .PHP_EOL;
        if (!empty($cf['enable_agent']) || !empty($cf['enable_fw_bouncer'])) {
            sleep(2);
            $crowdsec = trim(shell_exec("service crowdsec onestatus"));
            $crowdsec_status = strpos($crowdsec, "is running") > 0 ? "running" : "not running";
            // Handle crowdsec service
            if (!empty($cf['enable_agent'])){
                if($crowdsec_status !== 'running'){
                    $notice_content .= 'Crowdsec service is not running. Please check logs.' .PHP_EOL;
                }
                else {
                    // Handle pfsense collection
                    if (!file_exists(CROWDSEC_PFSENSE_COLLECTION)) {
                        $agent_conf = get_yaml_content(CROWDSEC_AGENT_CONF);
                        if (!empty($agent_conf)) {
                            $agent_conf['cscli']['hub_branch'] = "pfsense-gui";
                            set_yaml_content($agent_conf, CROWDSEC_AGENT_CONF);
                            shell_exec("cscli hub update");
                            exec("cscli --error collections install crowdsecurity/pfsense 2>&1", $output);

                            shell_exec("service crowdsec reload");

                            if (!empty($output)) {
                                $notice_content .= 'pfsense collection installation failed:  ' .
                                                   htmlspecialchars($output[0]) . PHP_EOL;

                                $notice_content .= 'Please run <b><i>cscli collections install crowdsecurity/pfsense</i></b> and <b><i>service crowdsec reload</i></b>.'
                                                   .PHP_EOL;
                            }
                            else {
                                $notice_content .= 'Installed collection crowdsecurity/pfsense.' . PHP_EOL;
                            }
                        }
                    }
                }
            }
            // Handle firewall bouncer
            if(!empty($cf['enable_fw_bouncer'])){
                $crowdsec_firewall = trim(shell_exec("service crowdsec_firewall onestatus"));
                $crowdsec_firewall_status = strpos($crowdsec_firewall, "is running") > 0 ? "running" : "not running";
                if($crowdsec_firewall_status !== 'running'){
                    $notice_content .= 'Crowdsec firewall bouncer is not running. Please check logs.' .PHP_EOL;
                }
            }
        }
        if (config_path_enabled('system','use_mfs_tmpvar')) {
            $notice_content .= "pfsense is set up to use a RAM disk for /var, the LAPI cannot be used because its database would be lost at every reboot. You can modify this settings <a href='/system_advanced_misc.php'>in this page.</a" .PHP_EOL;
        }
        file_put_contents(CROWDSEC_SETTINGS_NOTICE, $notice_content);
    }

}
/**
 * custom_php_after_head_command hook (setting edition after head)
 *
 * @return void
 */
function crowdsec_after_head(){

    $content= <<<EOF
    <div id="crowdsec-notice" class="alert alert-success" style="display:none;"></div>
EOF;

    echo $content;
}

/**
 * custom_php_after_form_command hook (setting edition after form)
 *
 * @return void
 */
function crowdsec_after_form()
{
    $content = '';
    if (file_exists(CROWDSEC_SETTINGS_NOTICE)) {
        $file_content = '';
        $fh = fopen(CROWDSEC_SETTINGS_NOTICE,'r');
        while ($line = fgets($fh)) {
            $file_content.= '<p>' . trim($line) .'</p>';
        }
        fclose($fh);
        $file_content = $file_content;

        $content .= <<<EOF
<script type="text/javascript">
//<![CDATA[
	events.push(function() {
	    $('#crowdsec-notice').show().html("$file_content");
	});
//]]>
</script>
EOF;
    }

    echo $content;
    unlink(CROWDSEC_SETTINGS_NOTICE);
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

