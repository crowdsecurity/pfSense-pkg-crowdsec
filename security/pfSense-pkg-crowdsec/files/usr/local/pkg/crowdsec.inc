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
    if (empty($post['enable_lapi'])) {
        if (empty($post['remote_lapi_port'])) {
            $input_errors[] = 'Remote LAPI port is required for remote LAPI.';
        } else {
            $remote_lapi_port = $post['remote_lapi_port'];
            if (!is_numeric($remote_lapi_port)) {
                $input_errors[] = 'Remote LAPI port must be a numeric value.';
            }
        }
        if (empty($post['remote_lapi_host'])) {
            $input_errors[] = 'Remote LAPI host is required for remote LAPI.';
        }
        if (empty($post['remote_agent_user'])) {
            $input_errors[] = 'Agent user is required for external LAPI usage.';
        }
        if (empty($post['remote_agent_password'])) {
            $input_errors[] = 'Agent password is required for external LAPI usage.';
        }
        if (empty($post['remote_fw_bouncer_api_key'])) {
            $input_errors[] = 'Firewall bouncer API key is required for external LAPI usage.';
        }
    } else {
        // Use Local API
        if (empty($post['lapi_port'])) {
            $input_errors[] = 'LAPI port is required for LAPI.';
        } else {
            $lapi_port = $post['lapi_port'];
            if (!is_numeric($lapi_port)) {
                $input_errors[] = 'LAPI port must be a numeric value.';
            }
        }
        if (empty($post['lapi_host'])) {
            $input_errors[] = 'LAPI host is required for LAPI.';
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
    $candidate_log_dir = '/var/log/crowdsec/';
    $candidate_log_max_size = 999999;
    global $crowdsec_aliases;
    // Prepare rc.conf.d variables
    mwexec('sysrc -f /usr/local/etc/rc.conf.d/crowdsec crowdsec_machine_name=pfsense');
    mwexec('sysrc -f /usr/local/etc/rc.conf.d/crowdsec_firewall crowdsec_firewall_name=pfsense-firewall');
    // UPDATE pfSense ALIAS TABLES
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
    // Modify bouncer yaml config
    $fw_conf = get_yaml_content(CROWDSEC_FIREWALL_CONF);
    if (!empty($fw_conf)) {
        $fw_conf['blacklists_ipv4'] = $crowdsec_aliases[0]['name'];
        $fw_conf['blacklists_ipv6'] = $crowdsec_aliases[1]['name'];
        $fw_conf['log_dir'] = $candidate_log_dir;
        $fw_conf['log_max_size'] = $candidate_log_max_size;
        $fw_conf['prometheus']['enabled'] = false;
        set_yaml_content($fw_conf, CROWDSEC_FIREWALL_CONF);
    }
    // Modify agent yaml config
    $agent_conf = get_yaml_content(CROWDSEC_AGENT_CONF);
    if (!empty($agent_conf)) {
        $agent_conf['common']['log_dir'] = $candidate_log_dir;
        $agent_conf['common']['log_max_size'] = $candidate_log_max_size;
        $agent_conf['db_config']['use_wal'] = true;
        set_yaml_content($agent_conf, CROWDSEC_AGENT_CONF);
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
 * Retrieve yaml content as an array
 *
 * @param $filepath
 * @return array|mixed
 */
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

/**
 * Write content in a yaml file
 *
 * @param $content
 * @param $filepath
 * @return void
 */
function set_yaml_content($content, $filepath)
{
    try {
        $yaml = Yaml::dump($content, 4);
        file_put_contents($filepath, $yaml);
    } catch (DumpException $exception) {
        syslog(LOG_ERR, 'Unable to dump ' . $filepath . ': ' . $exception->getMessage());
    }
}

function is_cs_service_running($name)
{
    $onestatus = trim(shell_exec("service $name onestatus"));

    return strpos($onestatus, "is running") > 0;
}

/**
 * custom_php_resync_config_command hook (install, setting edition, ...)
 *
 * @return void
 */
function crowdsec_resync_config()
{
    $cf = config_get_path('installedpackages/crowdsec/config/0', []);
    // Do not resync on first fresh install
    if (!$cf) {
        return;
    }
    // Init some flags to handle services management
    $should_use_agent = false;
    $should_use_firewall = false;
    // Init some flags to handle yaml overriding
    $update_lapi_yaml = false;
    $update_agent_yaml = false;
    $update_fw_yaml = false;
    // Retrieve yaml contents
    $lapi_conf = get_yaml_content(CROWDSEC_LAPI_CONF);
    $agent_conf = get_yaml_content(CROWDSEC_AGENT_CONF);
    $fw_conf = get_yaml_content(CROWDSEC_FIREWALL_CONF);
    // Handle LAPI ON
    if (!empty($cf['enable_lapi'])) {
        $should_use_agent = true;
        // Modify LAPI settings
        if (!empty($lapi_conf)) {
            if (!empty($cf['lapi_port']) && !empty($cf['lapi_host'])) {
                $lapi_url = $lapi_conf['url'] ?? '';
                $candidate_url = 'http://' . $cf['lapi_host'] . ':' . $cf['lapi_port'];
                if ($candidate_url !== $lapi_url) {
                    $lapi_conf['url'] = $candidate_url;
                    $update_lapi_yaml = true;
                }
            }
        }
        // Modify Agent yaml config
        if (!empty($agent_conf)) {
            $agent_conf['api']['server']['enable'] = true;
            $update_agent_yaml = true;
        }
        // Modify Firewall bouncer yaml config
        if (!empty($fw_conf)) {
            $fw_api_key = $fw_conf['api_key'] ?? '';
            $candidate_key = '${API_KEY}';
            if ($candidate_key !== $fw_api_key) {
                $fw_conf['api_key'] = $candidate_key;
                $update_fw_yaml = true;
            }
        }
        /**
         * Machine and bouncer will be created (and registered) again on next service start; so we delete them here.
         * @see /usr/local/etc/rc.d/crowdsec
         * @see /usr/local/etc/rc.d/crowdsec_firewall
         */
        mwexec('cscli bouncers delete pfsense-firewall');
        mwexec('cscli machines delete pfsense');
    } else { // Handle Remote LAPI ON (e.g. LAPI OFF)
        // Modify Agent yaml config
        if (!empty($agent_conf)) {
            $agent_conf['api']['server']['enable'] = false;
            $update_agent_yaml = true;
        }
        // Modify LAPI yaml config
        if (!empty($lapi_conf)) {
            if (!empty($cf['remote_agent_user']) && !empty($cf['remote_agent_password'])) {
                $lapi_login = $lapi_conf['login'] ?? '';
                $candidate_login = $cf['remote_agent_user'];
                if ($candidate_login !== $lapi_login) {
                    $lapi_conf['login'] = $candidate_login;
                    $update_lapi_yaml = true;
                }
                $lapi_password = $lapi_conf['password'] ?? '';
                $candidate_password = $cf['remote_agent_password'];
                if ($candidate_password !== $lapi_password) {
                    $lapi_conf['password'] = $candidate_password;
                    $update_lapi_yaml = true;
                }
            }
            if (!empty($cf['remote_lapi_port']) && !empty($cf['remote_lapi_host'])) {
                $lapi_url = $lapi_conf['url'] ?? '';
                $candidate_url = 'http://' . $cf['remote_lapi_host'] . ':' . $cf['remote_lapi_port'];
                if ($candidate_url !== $lapi_url) {
                    $lapi_conf['url'] = $candidate_url;
                    $update_lapi_yaml = true;
                }
            }
        }
        // Modify Firewall bouncer yaml config
        if (!empty($fw_conf)) {
            if (!empty($cf['remote_fw_bouncer_api_key'])) {
                $fw_api_key = $fw_conf['api_key'] ?? '';
                $candidate_key = $cf['remote_fw_bouncer_api_key'];
                if ($candidate_key !== $fw_api_key) {
                    $fw_conf['api_key'] = $candidate_key;
                    $update_fw_yaml = true;
                }
            }
            if (!empty($cf['remote_lapi_port']) && !empty($cf['remote_lapi_host'])) {
                $fw_url = $fw_conf['api_url'] ?? '';
                $candidate_url = 'http://' . $cf['remote_lapi_host'] . ':' . $cf['remote_lapi_port'] . '/';
                if ($candidate_url !== $fw_url) {
                    $fw_conf['api_url'] = $candidate_url;
                    $update_fw_yaml = true;
                }
            }
        }
    }

    // Handle Agent ON
    if (!empty($cf['enable_agent'])) {
        $should_use_agent = true;
        // Modify Agent yaml config
        if (!empty($agent_conf)) {
            $agent_crowdsec_service = $agent_conf['crowdsec_service']['enable'] ?? false;
            if (true !== $agent_crowdsec_service) {
                $agent_conf['crowdsec_service']['enable'] = true;
                $update_agent_yaml = true;
            }
            if (!empty($cf['lapi_port']) && !empty($cf['lapi_host'])) {
                $agent_url = $agent_conf['api']['server']['listen_uri'] ?? '';
                $candidate_url = $cf['lapi_host'] . ':' . $cf['lapi_port'];
                if ($candidate_url !== $agent_url) {
                    $agent_conf['api']['server']['listen_uri'] = $candidate_url;
                    $update_agent_yaml = true;
                }
            }
            if (!empty($cf['agent_log_level'])) {
                $agent_log_level = $agent_conf['common']['log_level'] ?? 'info';
                $candidate_level = $cf['agent_log_level'];
                if ($candidate_level !== $agent_log_level) {
                    $agent_conf['common']['log_level'] = $candidate_level;
                    $update_agent_yaml = true;
                }
            }
            if (!empty($cf['metrics_port'])) {
                $agent_metrics_port = $agent_conf['prometheus']['listen_port'] ?? 6060;
                $candidate_port = $cf['metrics_port'];
                if ($candidate_port !== $agent_metrics_port) {
                    $agent_conf['prometheus']['listen_port'] = (int)$candidate_port;
                    $update_agent_yaml = true;
                }
            }
        }
    } else {
        // Handle Agent OFF
        // Modify Agent yaml config
        if (!empty($agent_conf)) {
            $agent_crowdsec_service = $agent_conf['crowdsec_service']['enable'] ?? true;
            if (false !== $agent_crowdsec_service) {
                $agent_conf['crowdsec_service']['enable'] = false;
                $update_agent_yaml = true;
            }
        }
    }
    // Handle Firewall Bouncer ON
    if (!empty($cf['enable_fw_bouncer'])) {
        $should_use_firewall = true;
        if (!empty($fw_conf)) {
            if (!empty($cf['lapi_port']) && !empty($cf['lapi_host'])) {
                $fw_url = $fw_conf['api_url'] ?? '';
                $candidate_url = 'http://' . $cf['lapi_host'] . ':' . $cf['lapi_port'] . '/';
                if ($candidate_url !== $fw_url) {
                    $fw_conf['api_url'] = $candidate_url;
                    $update_fw_yaml = true;
                }
            }
            if (!empty($cf['firewall_bouncer_log_level'])) {
                $fw_log_level = $fw_conf['log_level'] ?? '';
                $candidate_level = $cf['firewall_bouncer_log_level'];
                if ($candidate_level !== $fw_log_level) {
                    $fw_conf['log_level'] = $candidate_level;
                    $update_fw_yaml = true;
                }
            }
            if (!empty($cf['metrics_firewall_port'])) {
                $fw_metrics_port = $fw_conf['prometheus']['listen_port'] ?? 6060;
                $candidate_port = $cf['metrics_firewall_port'];
                if ($candidate_port !== $fw_metrics_port) {
                    $fw_conf['prometheus']['listen_port'] = (int)$candidate_port;
                    $update_fw_yaml = true;
                }
            }
        }
    }
    // Override yaml contents
    if ($update_lapi_yaml) {
        set_yaml_content($lapi_conf, CROWDSEC_LAPI_CONF);
    }
    if ($update_fw_yaml) {
        set_yaml_content($fw_conf, CROWDSEC_FIREWALL_CONF);
    }
    if ($update_agent_yaml) {
        set_yaml_content($agent_conf, CROWDSEC_AGENT_CONF);
    }
    // Handle services management
    if ($should_use_agent) {
        mwexec('service crowdsec enable');
        // If we don't stop, the start command failed with message: crowdsec already running?
        if(is_cs_service_running('crowdsec')){
            mwexec("service crowdsec stop");
        }
        mwexec("service crowdsec start");
    } else {
        mwexec('service crowdsec stop');
        mwexec('service crowdsec disable');
    }

    if ($should_use_firewall) {
        mwexec('service crowdsec_firewall enable');
        // If we don't stop, the start command failed with message: crowdsec_firewall already running?
        if(is_cs_service_running('crowdsec_firewall')){
            mwexec("service crowdsec_firewall stop");
        }
        mwexec("service crowdsec_firewall start");
    } else {
        mwexec('service crowdsec_firewall stop');
        mwexec('service crowdsec_firewall disable');
    }

    // Check service statuses and notify user
    $notice_content = 'Settings saved.' . PHP_EOL;
    if ($should_use_agent || $should_use_firewall) {
        sleep(2);
        // Handle crowdsec service
        if ($should_use_agent) {
            if (!is_cs_service_running('crowdsec')) {
                $notice_content .= 'Crowdsec service is not running. Please check logs.' . PHP_EOL;
            } else {
                // Handle pfsense collection
                if (!file_exists(CROWDSEC_PFSENSE_COLLECTION)) {
                    $agent_conf = get_yaml_content(CROWDSEC_AGENT_CONF);
                    if (!empty($agent_conf)) {
                        $agent_conf['cscli']['hub_branch'] = "pfsense-gui";
                        set_yaml_content($agent_conf, CROWDSEC_AGENT_CONF);
                        shell_exec("cscli hub update");
                        exec("cscli --error collections install crowdsecurity/pfsense 2>&1", $output);
                        // We assume reloading won't fail
                        shell_exec("service crowdsec reload");

                        if (!empty($output)) {
                            $notice_content .= 'pfsense collection installation failed:  ' .
                                               htmlspecialchars($output[0]) . PHP_EOL;

                            $notice_content .= 'Please run <b><i>cscli collections install crowdsecurity/pfsense</i></b> and <b><i>service crowdsec reload</i></b>.'
                                               . PHP_EOL;
                        } else {
                            $notice_content .= 'Installed collection crowdsecurity/pfsense.' . PHP_EOL;
                        }
                    }
                }
            }
        }
        // Handle firewall bouncer
        if ($should_use_firewall) {
            if (!is_cs_service_running('crowdsec_firewall')) {
                $notice_content .= 'Crowdsec firewall bouncer is not running. Please check logs.' . PHP_EOL;
            }
        }
    }

    if (config_path_enabled('system', 'use_mfs_tmpvar')) {
        $notice_content .= "pfsense is set up to use a RAM disk for /var, the LAPI cannot be used because its database would be lost at every reboot. You can modify this settings <a href='/system_advanced_misc.php'>in this page.</a" .
                           PHP_EOL;
    }
    file_put_contents(CROWDSEC_SETTINGS_NOTICE, $notice_content);
}

/**
 * custom_php_after_head_command hook (setting edition after head)
 *
 * @return void
 */
function crowdsec_after_head()
{
    $content = <<<EOF
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
    $notice_content = '';
    if (file_exists(CROWDSEC_SETTINGS_NOTICE)) {
        $file_content = '';
        $fh = fopen(CROWDSEC_SETTINGS_NOTICE, 'r');
        while ($line = fgets($fh)) {
            $file_content .= '<p>' . trim($line) . '</p>';
        }
        fclose($fh);

        $notice_content = "$('#crowdsec-notice').show().html('$file_content');";
        unlink(CROWDSEC_SETTINGS_NOTICE);
    }

    $content = <<<EOF
<script type="text/javascript">
//<![CDATA[

    function disableRemote()
    {
        $('input[name="remote_lapi_host"]').prop('disabled', true);
        $('input[name="remote_lapi_port"]').prop('disabled', true);
        $('input[name="remote_agent_user"]').prop('disabled', true);
        $('input[name="remote_agent_password"]').prop('disabled', true);
        $('input[name="remote_fw_bouncer_api_key"]').prop('disabled', true);
        $('#enable_lapi').closest('div.panel-default').next().find('.panel-body').hide();
    }
    
    function enableRemote()
    {
        $('input[name="remote_lapi_host"]').prop('disabled', false);
        $('input[name="remote_lapi_port"]').prop('disabled', false);
        $('input[name="remote_agent_user"]').prop('disabled', false);
        $('input[name="remote_agent_password"]').prop('disabled', false);
        $('input[name="remote_fw_bouncer_api_key"]').prop('disabled', false);
        $('#enable_lapi').closest('div.panel-default').next().find('.panel-body').show();
    }
    
    events.push(function() {
        $notice_content
        
        $('input[name="enable_lapi"]').on( "change", function() {
            if( $(this).prop('checked') == true ){
             disableRemote();
            } else {
             enableRemote();
            }
        });
        
        if( $('input[name="enable_lapi"]').prop('checked') == true ){
             disableRemote();
         } else {
             enableRemote();
         }
        
        $("form").submit(function(){
              $('#submit').closest('div').html('<div class="loading"><i class="fa fa-spinner fa-spin"></i>Saving settings, please wait..</div>');
        });
    });
//]]>
</script>
EOF;

    echo $content;
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

