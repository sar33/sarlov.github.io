<?php
/**
* Plugin Name: Puckator Dropship Importer
* Description: Import Puckator products into WooCommerce with secure API auth, fuzzy keyword/SKU search, dynamic pricing (price + weight-based shipping + VAT + PayPal + profit), daily sync at 06:00 (site timezone), manual sync, and admin logs.
* Version: 3.2.2
* Author: WordPress Plugin AI
* Text Domain: puckator-dropship-importer
* License: GPLv2 or later
* License URI: https://www.gnu.org/licenses/gpl-2.0.html
* Requires PHP: 7.4
* Requires at least: 6.0
* Tested up to: 6.8
* Stable tag: 3.2.2
*/

if ( ! defined( 'ABSPATH' ) ) exit;

if ( ! defined( 'DISALLOW_FILE_EDIT' ) ) {
    define( 'DISALLOW_FILE_EDIT', true );
}

final class PDI_Plugin {
	const OPT_SETTINGS           = 'pdi_settings_v30';
	const OPT_LOGS               = 'pdi_logs_v30';
	const OPT_SECURITY_LOGS      = 'pdi_security_logs_v32';
	const TOKEN_TRANSIENT        = 'pdi_token_v30';
	const CACHE_VERSION_TRANSIENT = 'pdi_cache_version_v32';
	const CRON_HOOK              = 'pdi_daily_sync_v30';
	const LOG_CAP                = 800;
	const SECURITY_LOG_CAP       = 500;
	const META_SOURCE_FLAG       = '_pdi_source_v30';
	const META_SOURCE_SKU        = '_pdi_sku_v30';
	const DEFAULT_ENDPOINT       = '/rest/puck_dsuk/V1/customer/feed/products';
	const RATE_LIMIT_IMPORT      = 5;
	const RATE_LIMIT_SEARCH      = 10;
	const RATE_LIMIT_SYNC        = 2;
	const RATE_LIMIT_PERIOD      = 60;

	private static $instance = null;

	public static function instance() {
		if ( null === self::$instance ) self::$instance = new self();
		return self::$instance;
	}

	private function __construct() {
		add_action( 'admin_menu', [ $this, 'admin_menu' ] );
		add_action( 'admin_enqueue_scripts', [ $this, 'enqueue_admin' ] );
		add_action( 'admin_init', [ $this, 'add_security_headers' ] );

		add_action( 'wp_ajax_pdi_search', [ $this, 'ajax_search' ] );
		add_action( 'wp_ajax_pdi_import', [ $this, 'ajax_import' ] );
		add_action( 'wp_ajax_pdi_manual_sync', [ $this, 'ajax_manual_sync' ] );

		add_action( self::CRON_HOOK, [ $this, 'cron_sync' ] );

		register_activation_hook( __FILE__, [ $this, 'activate' ] );
		register_deactivation_hook( __FILE__, [ $this, 'deactivate' ] );
	}

	public function add_security_headers() {
		if ( is_admin() && isset( $_GET['page'] ) ) {
			$page = sanitize_text_field( wp_unslash( $_GET['page'] ) );
			if ( strpos( $page, 'pdi-' ) === 0 ) {
				header( 'X-Content-Type-Options: nosniff' );
				header( 'X-Frame-Options: DENY' );
				header( 'X-XSS-Protection: 1; mode=block' );
			}
		}
	}

	private function get_client_ip(): string {
		$ip = '';
		if ( ! empty( $_SERVER['HTTP_CLIENT_IP'] ) ) {
			$ip = sanitize_text_field( wp_unslash( $_SERVER['HTTP_CLIENT_IP'] ) );
		} elseif ( ! empty( $_SERVER['HTTP_X_FORWARDED_FOR'] ) ) {
			$forwarded = sanitize_text_field( wp_unslash( $_SERVER['HTTP_X_FORWARDED_FOR'] ) );
			$ips = explode( ',', $forwarded );
			$ip = isset( $ips[0] ) ? trim( $ips[0] ) : '';
		} elseif ( ! empty( $_SERVER['REMOTE_ADDR'] ) ) {
			$ip = sanitize_text_field( wp_unslash( $_SERVER['REMOTE_ADDR'] ) );
		}
		
		$ip = trim( $ip );
		if ( filter_var( $ip, FILTER_VALIDATE_IP ) ) {
			return $ip;
		}
		return 'unknown';
	}

	private function log_security_event( string $event, array $data = [] ) {
		$user = wp_get_current_user();
		$security_log = [
			'timestamp' => current_time( 'mysql' ),
			'user_id' => (int) $user->ID,
			'user_login' => isset( $user->user_login ) ? sanitize_text_field( $user->user_login ) : 'unknown',
			'ip_address' => $this->get_client_ip(),
			'event' => sanitize_text_field( $event ),
			'data' => wp_json_encode( $data ),
		];

		$logs = get_option( self::OPT_SECURITY_LOGS, [] );
		if ( ! is_array( $logs ) ) {
			$logs = [];
		}

		$logs[] = $security_log;
		$logs = array_slice( $logs, -self::SECURITY_LOG_CAP );
		update_option( self::OPT_SECURITY_LOGS, $logs, false );
	}

	private function check_rate_limit( string $action, int $limit = 10, int $period = 60 ): bool {
		$user_id = get_current_user_id();
		$key = "pdi_ratelimit_{$action}_{$user_id}";
		$count = (int) get_transient( $key );

		if ( $count >= $limit ) {
			$this->log_security_event( 'rate_limit_exceeded', [
				'action' => $action,
				'user_id' => $user_id,
				'limit' => $limit,
				'attempts' => $count,
			] );
			return false;
		}

		set_transient( $key, $count + 1, $period );
		return true;
	}

	private function minimize_item_for_client( array $p ): array {
		return [
			'sku'               => isset( $p['sku'] ) ? (string) $p['sku'] : '',
			'name'              => isset( $p['name'] ) ? (string) $p['name'] : ( $p['title'] ?? '' ),
			'title'             => isset( $p['title'] ) ? (string) $p['title'] : '',
			'description'       => isset( $p['description'] ) ? (string) $p['description'] : ( $p['short_description'] ?? '' ),
			'price'             => $this->extract_price( $p ),
			'weight'            => $this->extract_weight( $p ),
			'qty'               => $this->extract_stock( $p ),
			'cost'              => is_numeric( $p['cost'] ?? null ) ? (float) $p['cost'] : null,
			'price_ex_vat'      => is_numeric( $p['price_ex_vat'] ?? null ) ? (float) $p['price_ex_vat'] : null,
			'price_inc_vat'     => is_numeric( $p['price_inc_vat'] ?? null ) ? (float) $p['price_inc_vat'] : null,
			'shipping_weight'   => is_numeric( $p['shipping_weight'] ?? null ) ? (float) $p['shipping_weight'] : null,
		];
	}

	public function admin_menu() {
		add_menu_page( 'Puckator', 'Puckator', 'manage_options', 'pdi-dashboard', [ $this, 'page_dashboard' ], 'dashicons-cart', 56 );
		add_submenu_page( 'pdi-dashboard', 'Settings', 'Settings', 'manage_options', 'pdi-settings', [ $this, 'page_settings' ] );
		add_submenu_page( 'pdi-dashboard', 'Search & Import', 'Search & Import', 'edit_products', 'pdi-search', [ $this, 'page_search' ] );
		add_submenu_page( 'pdi-dashboard', 'Logs', 'Logs', 'manage_woocommerce', 'pdi-logs', [ $this, 'page_logs' ] );
	}

	public function enqueue_admin( $hook ) {
		$allowed = [
			'toplevel_page_pdi-dashboard',
			'puckator_page_pdi-settings',
			'puckator_page_pdi-search',
			'puckator_page_pdi-logs',
		];
		if ( ! in_array( $hook, $allowed, true ) ) {
			return;
		}

		wp_register_script( 'pdi-admin', false, [ 'jquery' ], '3.2.2', true );
		wp_enqueue_script( 'pdi-admin' );
		wp_add_inline_script( 'pdi-admin', $this->inline_js() );
		wp_localize_script( 'pdi-admin', 'PDI', [
			'ajax'  => admin_url( 'admin-ajax.php' ),
			'nonce' => wp_create_nonce( 'pdi_nonce' ),
		] );

		wp_register_style( 'pdi-admin-css', false, [], '3.2.2' );
		wp_enqueue_style( 'pdi-admin-css' );
		$css = '.pdi-row-imported { opacity: .6; } .pdi-badge-imported { display:inline-block; padding:2px 6px; font-size:11px; background:#e7f6ec; border:1px solid #9fd5b2; border-radius:3px; color:#1e7e34; margin-left:6px; } .pdi-row-imported input.pdi-item { pointer-events:none; }';
		wp_add_inline_style( 'pdi-admin-css', $css );
	}

	private function inline_js() {
		return 'jQuery(function($){$("#pdi-search-btn").on("click",function(){var kw=$("#pdi-keyword").val()||"";var bySku=$("#pdi-search-sku").is(":checked")?1:0;$("#pdi-results").html("Searching...");$.post(PDI.ajax,{action:"pdi_search",nonce:PDI.nonce,keyword:kw,sku_only:bySku}).done(function(resp){if(resp&&resp.success){$("#pdi-results").html(resp.data);}else{$("#pdi-results").html("Error: "+(resp.data||"Unknown error"));}}).fail(function(xhr){$("#pdi-results").html("Error: "+(xhr.responseText||xhr.status));});});$(document).on("click","#pdi-import-selected",function(){var items=[];$("input.pdi-item:checked").each(function(){items.push($(this).attr("data-item"));});if(!items.length){alert("Select products first");return;}$("#pdi-import-status").html("Importing...");$.post(PDI.ajax,{action:"pdi_import",nonce:PDI.nonce,items:items}).done(function(resp){if(resp&&resp.success){var msg="Imported: "+(resp.data&&resp.data.imported?resp.data.imported:0);if(resp.data&&resp.data.errors&&resp.data.errors.length){msg+="<br>Errors:<ul>";resp.data.errors.forEach(function(e){msg+="<li>"+$("<div>").text(e).html()+"</li>";});msg+="</ul>";}$("#pdi-import-status").html(msg);}else{$("#pdi-import-status").html(resp||"Done");}}).fail(function(xhr){$("#pdi-import-status").html("Error: "+(xhr.responseText||xhr.status));});});$("#pdi-sync-now").on("click",function(){if(!confirm("Run sync now?"))return;$("#pdi-sync-status").text("Sync running...");$.post(PDI.ajax,{action:"pdi_manual_sync",nonce:PDI.nonce}).done(function(html){$("#pdi-sync-status").html(html);}).fail(function(xhr){$("#pdi-sync-status").html("Error: "+(xhr.responseText||xhr.status));});});});';
	}

	public function page_dashboard() {
		if ( ! current_user_can( 'manage_options' ) ) wp_die( esc_html__( 'Unauthorized access.', 'puckator-dropship-importer' ) );
		$tz   = wp_timezone_string();
		$next = wp_next_scheduled( self::CRON_HOOK );
		echo '<div class="wrap"><h1>Puckator Dropship Importer</h1>';
		echo '<p>Daily sync runs at <strong>06:00</strong> using site timezone (<strong>' . esc_html( $tz ) . '</strong>).</p>';
		echo '<p>Next run: <strong>' . ( $next ? esc_html( wp_date( 'Y-m-d H:i', $next, wp_timezone() ) ) : 'not scheduled' ) . '</strong></p>';
		echo '<p><button id="pdi-sync-now" class="button button-primary">Sync now</button> <span id="pdi-sync-status"></span></p>';
		echo '</div>';
	}

	public function page_settings() {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'Unauthorized access.', 'puckator-dropship-importer' ) );
		}

		$s = $this->get_settings();
		$nonce_ok = false;

		if ( isset( $_POST['pdi_settings_nonce'] ) ) {
			$nonce_raw = sanitize_text_field( wp_unslash( $_POST['pdi_settings_nonce'] ) );
			$nonce_ok  = wp_verify_nonce( $nonce_raw, 'pdi_save_settings' );
		}

		if ( $nonce_ok ) {
			$this->log_security_event( 'settings_change_attempted', [
				'user_id' => get_current_user_id(),
			] );

			$save = [];

			$save['api_base'] = esc_url_raw( wp_unslash( $_POST['api_base'] ?? $s['api_base'] ) );
			if ( stripos( $save['api_base'], 'https://' ) !== 0 ) {
				$save['api_base'] = '';
				add_settings_error( 'pdi_settings', 'pdi_insecure_api_base', esc_html__( 'API Base URL must start with https://', 'puckator-dropship-importer' ), 'error' );
			}

			$endpoint_in = sanitize_text_field( wp_unslash( $_POST['endpoint'] ?? $s['endpoint'] ) );
			$endpoint_in = ltrim( $endpoint_in, '/' );
			if ( strlen( $endpoint_in ) > 512 || ! preg_match( '#^[a-z0-9/_\.\-\?\=\,&]*$#i', $endpoint_in ) ) {
				$endpoint_in = '';
				add_settings_error( 'pdi_settings', 'pdi_bad_endpoint', esc_html__( 'Endpoint contains invalid characters.', 'puckator-dropship-importer' ), 'error' );
			}
			$save['endpoint'] = $endpoint_in;

			$save['username'] = sanitize_email( wp_unslash( $_POST['username'] ?? '' ) );

			$current_raw = get_option( self::OPT_SETTINGS, [] );
			$current_encrypted_pw = isset( $current_raw['password'] ) ? (string) $current_raw['password'] : '';
			$plain_pw = isset( $_POST['password'] ) ? sanitize_text_field( wp_unslash( $_POST['password'] ) ) : '';
			$plain_pw = mb_substr( $plain_pw, 0, 256 );
			$save['password'] = $plain_pw !== '' ? $this->encrypt_field( $plain_pw ) : $current_encrypted_pw;

			$num_fields = [ 'vat', 'paypal_percent', 'paypal_fixed', 'profit_percent' ];
			foreach ( $num_fields as $field ) {
				$input_val = isset( $_POST[ $field ] ) ? sanitize_text_field( wp_unslash( $_POST[ $field ] ) ) : $s[ $field ];
				$val = (float) $this->nf( $input_val );
				if ( in_array( $field, [ 'vat', 'paypal_percent', 'profit_percent' ], true ) ) {
					$val = max( 0.00, min( 100.00, $val ) );
				} else {
					$val = max( 0.00, min( 100.00, $val ) );
				}
				$save[ $field ] = number_format( $val, 2, '.', '' );
			}

			$save['stock_field_path'] = sanitize_text_field( wp_unslash( $_POST['stock_field_path'] ?? $s['stock_field_path'] ) );
			$save['price_field_key']  = sanitize_text_field( wp_unslash( $_POST['price_field_key']  ?? $s['price_field_key']  ) );

			$shipping_json = isset( $_POST['shipping_table'] ) ? sanitize_text_field( wp_unslash( $_POST['shipping_table'] ) ) : ( $s['shipping_table'] ?? '' );
			if ( strlen( $shipping_json ) > 65536 ) {
				add_settings_error( 'pdi_settings', 'pdi_ship_oversize', esc_html__( 'Shipping table too large.', 'puckator-dropship-importer' ), 'error' );
				$shipping_json = '';
			}
			$decoded = json_decode( $shipping_json, true );
			if ( is_array( $decoded ) ) {
				$validated = [];
				foreach ( $decoded as $row ) {
					$min  = max( 0.0, (float) ( $row['min'] ?? 0.0 ) );
					$max  = max( $min, (float) ( $row['max'] ?? 0.0 ) );
					$cost = max( 0.0, (float) ( $row['cost'] ?? 0.0 ) );
					$validated[] = [ 'min' => $min, 'max' => $max, 'cost' => $cost ];
				}
				$save['shipping_table'] = wp_json_encode( $validated );
			} else {
				$save['shipping_table'] = '';
			}

			update_option( self::OPT_SETTINGS, $save, false );
			delete_transient( self::TOKEN_TRANSIENT );
			delete_transient( 'pdi_feed_cache' );
			delete_transient( self::CACHE_VERSION_TRANSIENT );

			$this->log( 'settings_saved', [ 'message' => 'Settings updated successfully.' ] );
			$this->log_security_event( 'settings_changed', [ 'user_id' => get_current_user_id() ] );
			echo '<div class="updated"><p>' . esc_html__( 'Settings saved.', 'puckator-dropship-importer' ) . '</p></div>';

			$s = $this->get_settings();
			$this->ensure_cron_scheduled();
		}

		settings_errors( 'pdi_settings' );
		?>
		<div class="wrap">
			<h1><?php echo esc_html__( 'Puckator Importer Settings', 'puckator-dropship-importer' ); ?></h1>
			<form method="post" action="">
				<?php wp_nonce_field( 'pdi_save_settings', 'pdi_settings_nonce' ); ?>
				<table class="form-table" role="presentation">
					<tbody>
						<tr>
							<th scope="row"><label for="api_base"><?php esc_html_e( 'API Base URL', 'puckator-dropship-importer' ); ?></label></th>
							<td><input name="api_base" type="url" id="api_base" value="<?php echo esc_attr( $s['api_base'] ); ?>" class="regular-text" placeholder="https://www.puckator-dropship.co.uk"></td>
						</tr>
						<tr>
							<th scope="row"><label for="endpoint"><?php esc_html_e( 'API Endpoint', 'puckator-dropship-importer' ); ?></label></th>
							<td><input name="endpoint" type="text" id="endpoint" value="<?php echo esc_attr( $s['endpoint'] ); ?>" class="regular-text" placeholder="/rest/puck_dsuk/V1/customer/feed/products"></td>
						</tr>
						<tr>
							<th scope="row"><label for="username"><?php esc_html_e( 'API Username (Email)', 'puckator-dropship-importer' ); ?></label></th>
							<td><input name="username" type="email" id="username" value="<?php echo esc_attr( $s['username'] ); ?>" class="regular-text"></td>
						</tr>
						<tr>
							<th scope="row"><label for="password"><?php esc_html_e( 'API Password', 'puckator-dropship-importer' ); ?></label></th>
							<td><input name="password" type="password" id="password" value="" placeholder="(leave blank to keep existing)" class="regular-text"></td>
						</tr>
						<tr>
							<th scope="row"><label for="vat"><?php esc_html_e( 'VAT %', 'puckator-dropship-importer' ); ?></label></th>
							<td><input name="vat" type="number" id="vat" value="<?php echo esc_attr( $s['vat'] ); ?>" step="0.01" min="0" max="100"></td>
						</tr>
						<tr>
							<th scope="row"><label for="paypal_percent"><?php esc_html_e( 'PayPal %', 'puckator-dropship-importer' ); ?></label></th>
							<td><input name="paypal_percent" type="number" id="paypal_percent" value="<?php echo esc_attr( $s['paypal_percent'] ); ?>" step="0.01" min="0" max="100"></td>
						</tr>
						<tr>
							<th scope="row"><label for="paypal_fixed"><?php esc_html_e( 'PayPal Fixed Fee', 'puckator-dropship-importer' ); ?></label></th>
							<td><input name="paypal_fixed" type="number" id="paypal_fixed" value="<?php echo esc_attr( $s['paypal_fixed'] ); ?>" step="0.01" min="0"></td>
						</tr>
						<tr>
							<th scope="row"><label for="profit_percent"><?php esc_html_e( 'Profit %', 'puckator-dropship-importer' ); ?></label></th>
							<td><input name="profit_percent" type="number" id="profit_percent" value="<?php echo esc_attr( $s['profit_percent'] ); ?>" step="0.01" min="0" max="100"></td>
						</tr>
						<tr>
							<th scope="row"><label for="stock_field_path"><?php esc_html_e( 'Stock Field Path (optional)', 'puckator-dropship-importer' ); ?></label></th>
							<td><input name="stock_field_path" type="text" id="stock_field_path" value="<?php echo esc_attr( $s['stock_field_path'] ); ?>" class="regular-text" placeholder="e.g. extension_attributes.stock_item.qty"></td>
						</tr>
						<tr>
							<th scope="row"><label for="price_field_key"><?php esc_html_e( 'Price Field Key (optional)', 'puckator-dropship-importer' ); ?></label></th>
							<td><input name="price_field_key" type="text" id="price_field_key" value="<?php echo esc_attr( $s['price_field_key'] ); ?>" class="regular-text" placeholder="e.g. price_ex_vat"></td>
						</tr>
						<tr>
							<th scope="row"><label for="shipping_table"><?php esc_html_e( 'Shipping Table (JSON)', 'puckator-dropship-importer' ); ?></label></th>
							<td>
								<textarea name="shipping_table" id="shipping_table" rows="5" class="large-text code"><?php echo esc_textarea( $s['shipping_table'] ); ?></textarea>
								<p class="description"><?php esc_html_e( 'Example: [{"min":0,"max":1,"cost":3.99},{"min":1,"max":2,"cost":5.99}]', 'puckator-dropship-importer' ); ?></p>
							</td>
						</tr>
					</tbody>
				</table>
				<?php submit_button( __( 'Save Settings', 'puckator-dropship-importer' ) ); ?>
			</form>
		</div>
		<?php
	}

	public function page_search() {
		if ( ! current_user_can( 'edit_products' ) ) {
			wp_die( esc_html__( 'Unauthorized access.', 'puckator-dropship-importer' ) );
		}
		?>
		<div class="wrap">
			<h1><?php echo esc_html__( 'Search & Import', 'puckator-dropship-importer' ); ?></h1>
			<p>
				<input id="pdi-keyword" type="text" class="regular-text" placeholder="<?php echo esc_attr__( 'Enter keyword or SKU', 'puckator-dropship-importer' ); ?>">
				<label style="margin-left:10px;">
					<input type="checkbox" id="pdi-search-sku" value="1">
					<?php echo esc_html__( 'Search by SKU only', 'puckator-dropship-importer' ); ?>
				</label>
				<button id="pdi-search-btn" class="button"><?php echo esc_html__( 'Search', 'puckator-dropship-importer' ); ?></button>
			</p>
			<div id="pdi-results"></div>
			<div id="pdi-import-status" style="margin-top:10px;"></div>
		</div>
		<?php
	}

	public function page_logs() {
		if ( ! current_user_can( 'manage_woocommerce' ) ) wp_die( esc_html__( 'Unauthorized access.', 'puckator-dropship-importer' ) );

		if ( isset( $_POST['pdi_clear_old_nonce'] ) && wp_verify_nonce( sanitize_text_field( wp_unslash( $_POST['pdi_clear_old_nonce'] ) ), 'pdi_clear_old' ) ) {
			$logs = get_option( self::OPT_LOGS, [] );
			if ( is_array( $logs ) && count( $logs ) > 100 ) {
				$logs = array_slice( $logs, -100 );
				update_option( self::OPT_LOGS, $logs, false );
				$this->log_security_event( 'logs_cleared', [ 'user_id' => get_current_user_id() ] );
				echo '<div class="updated"><p>🧹 ' . esc_html__( 'Old logs cleared. Kept latest 100 entries.', 'puckator-dropship-importer' ) . '</p></div>';
			} else {
				echo '<div class="notice notice-info"><p>' . esc_html__( 'No old logs to clear.', 'puckator-dropship-importer' ) . '</p></div>';
			}
		}

		$logs = get_option( self::OPT_LOGS, [] );
		$logs = is_array( $logs ) ? array_reverse( $logs ) : [];

		ob_start();
		wp_nonce_field( 'pdi_clear_old', 'pdi_clear_old_nonce' );
		$nonce_field = ob_get_clean();
		echo '<div class="wrap"><h1 style="display:flex;justify-content:space-between;align-items:center;">' .
			esc_html__( 'Logs', 'puckator-dropship-importer' ) .
			'<form method="post" onsubmit="return confirm(\'Are you sure you want to remove old logs (keeping last 100)?\');" style="margin:0;">' .
			wp_kses_post( $nonce_field ) .
			'<button type="submit" class="button">🧹 ' .
			esc_html__( 'Clear Old Logs', 'puckator-dropship-importer' ) .
			'</button></form></h1>';
		if ( empty( $logs ) ) {
			echo '<p>' . esc_html__( 'No logs yet.', 'puckator-dropship-importer' ) . '</p></div>';
			return;
		}
		echo '<style>
			.pdi-log-table td, .pdi-log-table th { vertical-align: top; }
			.pdi-log-table pre { background: #f6f7f7; padding: 6px; border-radius: 3px; overflow-x: auto; }
			details summary { cursor: pointer; color: #0073aa; margin-top: 4px; }
			details[open] summary { color: #2271b1; }
			.pdi-detail-table { margin-top: 6px; border-collapse: collapse; width: 100%; background: #fff; }
			.pdi-detail-table th, .pdi-detail-table td { border: 1px solid #ddd; padding: 4px 6px; }
			.pdi-detail-table th { background: #f9f9f9; }
			.pdi-log-table .pdi-note { color: #666; font-size: 12px; }
			.pdi-row-success { border-left: 4px solid #46b450; background: #f5fbf5; }
			.pdi-row-info    { border-left: 4px solid #00a0d2; background: #f7fcff; }
			.pdi-row-error   { border-left: 4px solid #dc3232; background: #fff5f5; }
		</style>';

		echo '<table class="widefat striped pdi-log-table">';
		echo '<thead><tr><th>' . esc_html__( 'Date', 'puckator-dropship-importer' ) . '</th><th>' . esc_html__( 'Action', 'puckator-dropship-importer' ) . '</th><th>' . esc_html__( 'Summary', 'puckator-dropship-importer' ) . '</th></tr></thead><tbody>';

		foreach ( $logs as $row ) {
			$date   = isset( $row['ts'] ) ? wp_date( 'Y-m-d H:i:s', intval( $row['ts'] ), wp_timezone() ) : '';
			$action = isset( $row['action'] ) ? esc_html( $row['action'] ) : '';
			$data   = $row['data'] ?? [];

			$class = 'pdi-row-info';
			if ( stripos( $action, 'error' ) !== false || isset( $data['error'] ) ) {
				$class = 'pdi-row-error';
			} elseif ( in_array( $action, [ 'sync', 'import', 'settings_saved' ], true ) ) {
				$class = 'pdi-row-success';
			} elseif ( in_array( $action, [ 'sync_progress', 'sync_skipped' ], true ) ) {
				$class = 'pdi-row-info';
			}

			$summary = '';
			if ( isset( $data['updated'] ) ) {
				$summary .= '<p>✅ ' . sprintf( esc_html__( 'Updated %d products.', 'puckator-dropship-importer' ), intval( $data['updated'] ) ) . '</p>';
			}
			if ( isset( $data['count'] ) ) {
				$summary .= '<p>✅ ' . sprintf( esc_html__( 'Imported %d products.', 'puckator-dropship-importer' ), intval( $data['count'] ) ) . '</p>';
			}
			if ( isset( $data['message'] ) ) {
				$summary .= '<p>⚙️ ' . esc_html( $data['message'] ) . '</p>';
			}
			if ( isset( $data['note'] ) ) {
				$summary .= '<p class="pdi-note">' . esc_html( $data['note'] ) . '</p>';
			}
			if ( isset( $data['error'] ) ) {
				$summary .= '<p style="color:#b30000;">❌ ' . esc_html( $data['error'] ) . '</p>';
			}
			if ( ! empty( $data['details'] ) && is_array( $data['details'] ) ) {
				$summary .= '<details><summary>' . esc_html__( 'Show Details', 'puckator-dropship-importer' ) . '</summary>';
				$summary .= '<table class="pdi-detail-table"><thead><tr><th>' . esc_html__( 'Product ID', 'puckator-dropship-importer' ) . '</th><th>' . esc_html__( 'SKU', 'puckator-dropship-importer' ) . '</th><th>' . esc_html__( 'Changes', 'puckator-dropship-importer' ) . '</th></tr></thead><tbody>';
				foreach ( $data['details'] as $detail ) {
					$pid = esc_html( $detail['product_id'] ?? '' );
					$sku = esc_html( $detail['sku'] ?? '' );
					$changes = '';
					if ( isset( $detail['changed'] ) && is_array( $detail['changed'] ) ) {
						foreach ( $detail['changed'] as $field => $vals ) {
							$from = isset( $vals['from'] ) ? esc_html( $vals['from'] ) : '';
							$to   = isset( $vals['to'] )   ? esc_html( $vals['to'] )   : '';
							$changes .= '<div>' . esc_html( ucfirst( $field ) ) . ': ' . esc_html( $from ) . ' → ' . esc_html( $to ) . '</div>';
						}
					}
					if ( $changes === '' ) {
						$changes = '<span class="pdi-note">' . esc_html__( 'No details', 'puckator-dropship-importer' ) . '</span>';
					}
					$summary .= '<tr><td>' . $pid . '</td><td>' . $sku . '</td><td>' . $changes . '</td></tr>';
				}
				$summary .= '</tbody></table></details>';
			}
			if ( $summary === '' && ! empty( $data ) ) {
				$pretty = wp_json_encode( $data, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES );
				$summary = '<pre>' . esc_html( $pretty ) . '</pre>';
			}

			echo '<tr class="' . esc_attr( $class ) . '">';
			echo '<td>' . esc_html( $date ) . '</td>';
			echo '<td>' . esc_html( $action ) . '</td>';
			echo '<td>' . wp_kses_post( $summary ) . '</td>';
			echo '</tr>';
		}

		echo '</tbody></table></div>';
	}

	private function safe_decode_json_item( $raw, $max_len = 65536 ) {
		if ( ! is_string( $raw ) ) return new WP_Error( 'bad_item', 'Invalid item type' );
		$raw = wp_unslash( $raw );
		if ( ! seems_utf8( $raw ) ) return new WP_Error( 'bad_utf8', 'Invalid UTF-8' );
		if ( strlen( $raw ) > $max_len ) return new WP_Error( 'too_big', 'Item too large' );
		$decoded = json_decode( $raw, true );
		if ( json_last_error() !== JSON_ERROR_NONE || ! is_array( $decoded ) ) return new WP_Error( 'bad_json', 'Invalid item payload' );
		return $decoded;
	}

	private function verify_cache_integrity( array $cache ): bool {
		if ( empty( $cache ) ) {
			return true;
		}
		foreach ( array_keys( $cache ) as $sku ) {
			if ( ! is_string( $sku ) || strlen( $sku ) > 100 ) {
				return false;
			}
			if ( ! preg_match( '/^[A-Z0-9\-_]+$/i', $sku ) ) {
				return false;
			}
		}
		return true;
	}

	private function get_all_store_skus(): array {
		global $wpdb;
		$count = (int) $wpdb->get_var(
			$wpdb->prepare(
				"SELECT COUNT(*) FROM {$wpdb->postmeta} pm INNER JOIN {$wpdb->posts} p ON p.ID = pm.post_id WHERE pm.meta_key = %s AND p.post_type = %s",
				'_sku', 'product'
			)
		);
		
		if ( $count > 50000 ) {
			return [];
		}
		
		$cache_version = get_transient( self::CACHE_VERSION_TRANSIENT );
		if ( ! $cache_version ) {
			$cache_version = wp_generate_password( 12, false );
			set_transient( self::CACHE_VERSION_TRANSIENT, $cache_version, 24 * HOUR_IN_SECONDS );
		}
		$cache_key = 'pdi_skus_cache_' . $cache_version;
		
		$cache = get_transient( $cache_key );
		if ( is_array( $cache ) && $this->verify_cache_integrity( $cache ) ) {
			return $cache;
		}
		
		$query = $wpdb->prepare(
			"SELECT pm.meta_value FROM {$wpdb->postmeta} pm
			INNER JOIN {$wpdb->posts} p ON p.ID = pm.post_id
			WHERE pm.meta_key = %s AND p.post_type = %s",
			'_sku',
			'product'
		);
		$rows = $wpdb->get_col( $query );
		$out = [];
		if ( $rows ) {
			foreach ( $rows as $sku ) {
				$sku = strtoupper( trim( (string) $sku ) );
				if ( $sku !== '' && preg_match( '/^[A-Z0-9\-_]+$/i', $sku ) ) {
					$out[ $sku ] = true;
				}
			}
		}
		set_transient( $cache_key, $out, 5 * MINUTE_IN_SECONDS );
		return $out;
	}

	private function get_by_path( array $data, string $path ) {
		$path = trim( $path );
		if ( $path === '' ) return null;
		$parts = array_values( array_filter( explode( '.', $path ), static function( $p ) {
			return $p !== '';
		} ) );
		if ( empty( $parts ) || count( $parts ) > 12 ) {
			return null;
		}
		$cursor = $data;
		foreach ( $parts as $seg ) {
			if ( $seg === '.' || $seg === '..' ) return null;
			if ( is_array( $cursor ) && array_key_exists( $seg, $cursor ) ) {
				$cursor = $cursor[ $seg ];
			} else {
				if ( is_array( $cursor ) && array_key_exists( (string) $seg, $cursor ) ) {
					$cursor = $cursor[ (string) $seg ];
				} else {
					return null;
				}
			}
		}
		return $cursor;
	}

	public function ajax_import() {
		if ( ! current_user_can( 'edit_products' ) ) {
			wp_send_json_error( [ 'message' => 'Unauthorized' ], 403 );
		}
		if ( ! check_ajax_referer( 'pdi_nonce', 'nonce', false ) ) {
			wp_send_json_error( [ 'message' => 'Invalid nonce' ], 403 );
		}
		
		if ( ! $this->check_rate_limit( 'import', self::RATE_LIMIT_IMPORT, self::RATE_LIMIT_PERIOD ) ) {
			wp_send_json_error( [ 'message' => 'Rate limit exceeded. Please wait.' ], 429 );
		}
		
		if ( ! class_exists( 'WC_Product' ) ) {
			wp_send_json_error( [ 'message' => 'WooCommerce is required.' ], 400 );
		}
		$items_raw = [];
		if ( isset( $_POST['items'] ) && is_array( $_POST['items'] ) ) {
			foreach ( $_POST['items'] as $raw_item ) {
				$decoded = sanitize_text_field( wp_unslash( $raw_item ) );
				$items_raw[] = $decoded;
			}
		}
		if ( empty( $items_raw ) ) {
			wp_send_json_error( [ 'message' => 'No items selected.' ], 400 );
		}
		$max_items = 200;
		if ( count( $items_raw ) > $max_items ) {
			$items_raw = array_slice( $items_raw, 0, $max_items );
		}
		$imported = 0;
		$errors   = [];
		$sku_cache = $this->get_all_store_skus();
		$use_memcache = count( $sku_cache ) > 0;
		foreach ( $items_raw as $raw_json ) {
			$item = $this->safe_decode_json_item( $raw_json );
			if ( is_wp_error( $item ) ) {
				$errors[] = $item->get_error_message();
				continue;
			}
			$sku_check = isset( $item['sku'] ) ? trim( (string) $item['sku'] ) : '';
			$exists = false;
			if ( $sku_check !== '' ) {
				if ( $use_memcache ) {
					$exists = isset( $sku_cache[ strtoupper( $sku_check ) ] );
				} else {
					$exists = wc_get_product_id_by_sku( $sku_check ) ? true : false;
				}
			}
			if ( $exists ) {
				$errors[] = sprintf( 'SKU %s already imported, skipped.', esc_html( $sku_check ) );
				continue;
			}
			$res = $this->create_or_update_wc_product( $item );
			if ( is_wp_error( $res ) ) {
				$errors[] = $res->get_error_message();
			} else {
				$imported++;
			}
		}
		if ( $imported ) {
			$this->log( 'import', [ 'count' => $imported ] );
			$this->log_security_event( 'products_imported', [ 'count' => $imported, 'user_id' => get_current_user_id() ] );
		}
		wp_send_json_success( [
			'imported' => $imported,
			'errors'   => $errors,
		] );
	}

	public function ajax_search() {
		if ( ! current_user_can( 'edit_products' ) ) {
			wp_send_json_error( 'Unauthorized', 403 );
		}
		if ( ! check_ajax_referer( 'pdi_nonce', 'nonce', false ) ) {
			wp_send_json_error( 'Invalid nonce', 403 );
		}
		
		if ( ! $this->check_rate_limit( 'search', self::RATE_LIMIT_SEARCH, self::RATE_LIMIT_PERIOD ) ) {
			wp_send_json_error( 'Rate limit exceeded. Please wait.', 429 );
		}
		
		$kw = sanitize_text_field( wp_unslash( $_POST['keyword'] ?? '' ) );
		$kw = mb_substr( $kw, 0, 200 );
		$sku_only = ! empty( $_POST['sku_only'] ) && filter_var( wp_unslash( $_POST['sku_only'] ), FILTER_VALIDATE_BOOLEAN );
		$feed = $this->fetch_feed();
		if ( is_wp_error( $feed ) ) {
			$this->log( 'search_error', [ 'error' => $feed->get_error_message() ] );
			wp_send_json_error( $feed->get_error_message(), 500 );
		}
		$products = $this->extract_products( $feed );
		if ( $kw !== '' ) {
			$products = $this->fuzzy_filter( $products, $kw, (bool) $sku_only );
		}
		if ( empty( $products ) ) {
			wp_send_json_success( '<p>' . esc_html__( 'No results found.', 'puckator-dropship-importer' ) . '</p>' );
		}
		$products = array_slice( $products, 0, 500 );
		ob_start();
		$existing = $this->get_all_store_skus();
		$s = $this->get_settings();
		echo '<table class="widefat striped">';
		echo '<thead><tr><th></th><th>' . esc_html__( 'SKU', 'puckator-dropship-importer' ) . '</th><th>' . esc_html__( 'Name', 'puckator-dropship-importer' ) . '</th><th>' . esc_html__( 'Price (£)', 'puckator-dropship-importer' ) . '</th><th>' . esc_html__( 'Shipping (£)', 'puckator-dropship-importer' ) . '</th><th>' . esc_html__( 'VAT (£)', 'puckator-dropship-importer' ) . '</th><th>' . esc_html__( 'PayPal (£)', 'puckator-dropship-importer' ) . '</th><th>' . esc_html__( 'Profit (£)', 'puckator-dropship-importer' ) . '</th><th>' . esc_html__( 'Final (£)', 'puckator-dropship-importer' ) . '</th><th>' . esc_html__( 'Weight (kg)', 'puckator-dropship-importer' ) . '</th><th>' . esc_html__( 'Stock', 'puckator-dropship-importer' ) . '</th></tr></thead><tbody>';
		foreach ( $products as $p ) {
			$sku     = sanitize_text_field( $p['sku'] ?? '' );
			$name    = sanitize_text_field( $p['name'] ?? ( $p['title'] ?? '' ) );
			$price   = (float) $this->extract_price( $p );
			$weight  = (float) $this->extract_weight( $p );
			$qty     = (int)   $this->extract_stock( $p );
			$ship    = (float) $this->get_shipping_for_weight( $weight );
			$base     = $price + $ship;
			$vat      = $base * ( (float) $s['vat'] / 100 );
			$paypal   = (float) $s['paypal_fixed'] + $base * ( (float) $s['paypal_percent'] / 100 );
			$subtotal = $base + $vat + $paypal;
			$final    = max( 0, round( $subtotal * ( 1 + ( (float) $s['profit_percent'] / 100 ) ), 2 ) );
			$profit   = $final - $subtotal;
			$price_f   = number_format( $price, 2 );
			$ship_f    = number_format( $ship, 2 );
			$vat_f     = number_format( $vat, 2 );
			$paypal_f  = number_format( $paypal, 2 );
			$profit_f  = number_format( $profit, 2 );
			$final_f   = number_format( $final, 2 );
			$weight_f  = number_format( $weight, 2 );
			$imported  = isset( $existing[ strtoupper( $sku ) ] );
			$row_class = $imported ? 'pdi-row-imported' : '';
			$badge     = $imported ? '<span class="pdi-badge-imported">' . esc_html__( 'Imported', 'puckator-dropship-importer' ) . '</span>' : '';
			$esc_json = esc_attr( wp_json_encode( $p, JSON_HEX_APOS | JSON_HEX_QUOT | JSON_HEX_AMP ) );
			echo '<tr class="' . esc_attr( $row_class ) . '"><td><input type="checkbox" class="pdi-item" data-item="' . $esc_json . '" ' . ( $imported ? 'disabled' : '' ) . '></td><td>' . esc_html( $sku ) . ' ' . $badge . '</td><td>' . esc_html( $name ) . '</td><td>£' . esc_html( $price_f ) . '</td><td>£' . esc_html( $ship_f ) . '</td><td>£' . esc_html( $vat_f ) . '</td><td>£' . esc_html( $paypal_f ) . '</td><td>£' . esc_html( $profit_f ) . '</td><td>£' . esc_html( $final_f ) . '</td><td>' . esc_html( $weight_f ) . '</td><td>' . esc_html( $qty ) . '</td></tr>';
		}
		echo '</tbody></table><p><button id="pdi-import-selected" class="button button-primary">' . esc_html__( 'Import Selected', 'puckator-dropship-importer' ) . '</button></p>';
		$html = ob_get_clean();
		wp_send_json_success( $html );
	}

	public function ajax_manual_sync() {
		if ( ! current_user_can( 'manage_woocommerce' ) ) {
			wp_send_json_error( 'Unauthorized', 403 );
		}
		if ( ! check_ajax_referer( 'pdi_nonce', 'nonce', false ) ) {
			wp_send_json_error( 'Invalid nonce', 403 );
		}
		
		if ( ! $this->check_rate_limit( 'sync', self::RATE_LIMIT_SYNC, self::RATE_LIMIT_PERIOD * 5 ) ) {
			wp_send_json_error( 'Sync already running or rate limit exceeded. Please wait.', 429 );
		}
		
		$result = $this->sync_products();
		if ( is_wp_error( $result ) ) {
			status_header( 500 );
			echo '<div class="notice notice-error"><p>' . esc_html( $result->get_error_message() ) . '</p></div>';
		} else {
			$this->log_security_event( 'manual_sync', [ 'updated' => $result['updated'], 'user_id' => get_current_user_id() ] );
			echo esc_html( sprintf( __( 'Synced %d product(s).', 'puckator-dropship-importer' ), intval( $result['updated'] ) ) );
		}
		wp_die();
	}

	public function activate() {
		$this->ensure_cron_scheduled();
		if ( get_option( self::OPT_SETTINGS, null ) === null ) {
			add_option( self::OPT_SETTINGS, [], '', 'no' );
		}
		if ( get_option( self::OPT_LOGS, null ) === null ) {
			add_option( self::OPT_LOGS, [], '', 'no' );
		}
		if ( get_option( self::OPT_SECURITY_LOGS, null ) === null ) {
			add_option( self::OPT_SECURITY_LOGS, [], '', 'no' );
		}
	}

	public function deactivate() { 
		wp_clear_scheduled_hook( self::CRON_HOOK ); 
	}

	private function ensure_cron_scheduled() {
		if ( ! wp_next_scheduled( self::CRON_HOOK ) ) {
			$tz  = wp_timezone();
			$now = new DateTime( 'now', $tz );
			$run = new DateTime( 'today 06:00:00', $tz );
			if ( $run <= $now ) $run->modify( '+1 day' );
			wp_schedule_event( $run->getTimestamp(), 'daily', self::CRON_HOOK );
		}
	}

	public function cron_sync() { 
		$this->sync_products(); 
	}

	private function sync_products() {
		if ( ! class_exists( 'WC_Product' ) ) {
			return new WP_Error( 'no_wc', 'WooCommerce is required.' );
		}
		$lock_key = 'pdi_sync_lock_' . substr( md5( home_url() ), 0, 16 );
		$now      = time();
		$lock     = get_transient( $lock_key );
		if ( $lock && ( $now - (int) $lock ) < 1800 ) {
			$this->log( 'sync_skipped', [ 'reason' => 'locked' ] );
			return [ 'updated' => 0 ];
		}
		set_transient( $lock_key, $now, 30 * MINUTE_IN_SECONDS );
		try {
			$feed = $this->fetch_feed( true );
			if ( is_wp_error( $feed ) ) {
				$this->log( 'sync_error', [ 'error' => $feed->get_error_message() ] );
				return $feed;
			}
			$list = $this->extract_products( $feed );
			if ( empty( $list ) ) {
				$this->log( 'sync', [ 'updated' => 0, 'note' => 'Feed empty' ] );
				return [ 'updated' => 0 ];
			}
			$by_sku = [];
			foreach ( $list as $item ) {
				$sku = isset( $item['sku'] ) ? trim( (string) $item['sku'] ) : '';
				if ( $sku !== '' ) {
					$by_sku[ strtoupper( $sku ) ] = $item;
				}
			}
			$batch_size = 400;
			$paged      = 1;
			$updated    = 0;
			$report     = [];
			$restore_cache_flag = wp_suspend_cache_addition( true );
			do {
				$q = new WP_Query( [
					'post_type'      => 'product',
					'post_status'    => 'any',
					'fields'         => 'ids',
					'posts_per_page' => $batch_size,
					'paged'          => $paged,
					'no_found_rows'  => true,
					'orderby'        => 'ID',
					'order'          => 'ASC',
					'meta_query'     => [ [ 'key' => '_sku', 'compare' => 'EXISTS' ] ],
					'update_post_meta_cache' => false,
					'update_post_term_cache' => false,
				] );
				$ids = $q->posts;
				if ( empty( $ids ) ) break;
				foreach ( $ids as $pid ) {
					$sku = (string) get_post_meta( $pid, '_sku', true );
					if ( $sku === '' ) continue;
					$key = strtoupper( trim( $sku ) );
					if ( ! isset( $by_sku[ $key ] ) ) continue;
					$item   = $by_sku[ $key ];
					$before = [
						'price' => (float) get_post_meta( $pid, '_regular_price', true ),
						'stock' => (int)   get_post_meta( $pid, '_stock', true ),
					];
					$res = $this->create_or_update_wc_product( $item, $pid );
					if ( is_wp_error( $res ) ) continue;
					$after = [
						'price' => (float) get_post_meta( $pid, '_regular_price', true ),
						'stock' => (int)   get_post_meta( $pid, '_stock', true ),
					];
					$changed = [];
					if ( $after['price'] !== $before['price'] ) {
						$changed['price'] = [ 'from' => $before['price'], 'to' => $after['price'] ];
					}
					if ( $after['stock'] !== $before['stock'] ) {
						$changed['stock'] = [ 'from' => $before['stock'], 'to' => $after['stock'] ];
					}
					if ( $changed ) {
						$updated++;
						$report[] = [ 'product_id' => $pid, 'sku' => $sku, 'changed' => $changed ];
					}
				}
				$this->log( 'sync_progress', [ 'batch' => $paged, 'updated' => $updated ] );
				$paged++;
				wp_reset_postdata();
				$more = ( count( $ids ) === $batch_size );
			} while ( $more );
			wp_suspend_cache_addition( $restore_cache_flag );
			$this->log( 'sync', [ 'updated' => $updated, 'details' => $report, 'note' => 'Matched by SKU (batched with progress)' ] );
			return [ 'updated' => $updated ];
		} finally {
			delete_transient( $lock_key );
		}
	}

	private function create_or_update_wc_product( array $item, $existing_id = 0 ) {
		$sku = strtoupper( sanitize_text_field( $item['sku'] ?? '' ) );
		if ( $sku === '' ) return new WP_Error( 'no_sku', 'Item has no SKU.' );
		
		if ( ! preg_match( '/^[A-Z0-9\-_]+$/i', $sku ) ) {
			return new WP_Error( 'invalid_sku', 'SKU contains invalid characters.' );
		}

		$title = sanitize_text_field( $item['name'] ?? ( $item['title'] ?? 'Untitled' ) );
		if ( strlen( $title ) > 200 ) {
			$title = substr( $title, 0, 200 );
		}

		$desc  = wp_kses( 
			$item['description'] ?? ( $item['short_description'] ?? '' ),
			[ 'p' => [], 'br' => [], 'strong' => [], 'em' => [], 'ul' => [], 'ol' => [], 'li' => [] ]
		);

		$cost  = (float) $this->extract_price( $item );
		$stock = (int)   $this->extract_stock( $item );
		$weight        = (float) $this->extract_weight( $item );
		$shipping_cost = $this->get_shipping_for_weight( $weight );

		$s        = $this->get_settings();
		$base     = $cost + $shipping_cost;
				$vat      = $base * ( (float) $s['vat'] / 100 );
		$pp       = (float) $s['paypal_fixed'] + $base * ( (float) $s['paypal_percent'] / 100 );
		$subtotal = $base + $vat + $pp;
		$final    = max( 0, round( $subtotal * ( 1 + ( (float) $s['profit_percent'] / 100 ) ), 2 ) );
		$final_s  = number_format( (float) $final, 2, '.', '' );

		$product_id = $existing_id ?: wc_get_product_id_by_sku( $sku );
		$product    = $product_id ? wc_get_product( $product_id ) : new WC_Product_Simple();
		if ( ! $product ) return new WP_Error( 'not_found', 'Product not found.' );

		$product->set_name( $title );
		$product->set_description( $desc );
		$product->set_sku( $sku );
		$product->set_regular_price( $final_s );
		$product->set_manage_stock( true );
		$product->set_stock_quantity( $stock );

		if ( ! $product_id ) {
			$product->set_status( 'draft' );
		}

		$product_id = $product->save();
		update_post_meta( $product_id, self::META_SOURCE_FLAG, 1 );
		update_post_meta( $product_id, self::META_SOURCE_SKU,  $sku );

		return $product_id;
	}

	private function fetch_feed( bool $bypass_cache = false ) {
		$token = $this->get_token();
		if ( ! $token ) {
			return new WP_Error( 'token', 'Failed to get token.' );
		}

		$s        = $this->get_settings();
		$endpoint = ltrim( (string) ( $s['endpoint'] ?? '' ), '/' );

		if ( $endpoint === '' || strlen( $endpoint ) > 512 ||
			strpos( $endpoint, '..' ) !== false ||
			strpos( $endpoint, '//' ) !== false ||
			preg_match( '#%2f#i', $endpoint ) ||
			! preg_match( '#^[a-z0-9/_\.\-\?\=\,&]*$#i', $endpoint ) ) {
			return new WP_Error( 'bad_endpoint', 'Invalid endpoint format.' );
		}

		$api_base = (string) ( $s['api_base'] ?? '' );
		$host     = wp_parse_url( $api_base, PHP_URL_HOST );

		$allowed_hosts = apply_filters( 'pdi_allowed_api_hosts', [
			'www.puckator-dropship.co.uk',
			'puckator-dropship.co.uk',
		] );

		if ( ! in_array( $host, (array) $allowed_hosts, true ) ) {
			return new WP_Error( 'bad_host', 'API host is not allowed.' );
		}

		$url = untrailingslashit( $api_base ) . '/' . $endpoint;

		if ( stripos( $url, 'https://' ) !== 0 ) {
			return new WP_Error( 'insecure_url', 'HTTPS required.' );
		}

		if ( ! $bypass_cache ) {
			$cached = get_transient( 'pdi_feed_cache' );
			if ( $cached && is_array( $cached ) ) {
				return $cached;
			}
		}

		$res = wp_safe_remote_get( $url, [
			'headers' => [
				'Authorization' => 'Bearer ' . $token,
				'Accept'        => 'application/json',
			],
			'timeout'             => 30,
			'redirection'         => 3,
			'reject_unsafe_urls'  => true,
			'limit_response_size' => 10 * 1024 * 1024,
		] );

		if ( is_wp_error( $res ) ) {
			return $res;
		}

		$code = (int) wp_remote_retrieve_response_code( $res );
		$body = (string) wp_remote_retrieve_body( $res );

		if ( $code !== 200 ) {
			return new WP_Error( 'http', 'Feed HTTP ' . $code );
		}

		if ( strlen( $body ) > 10 * 1024 * 1024 ) {
			return new WP_Error( 'oversize', 'Feed too large.' );
		}

		$data = json_decode( $body, true );
		if ( ! is_array( $data ) ) {
			return new WP_Error( 'json', 'Invalid JSON from feed.' );
		}

		set_transient( 'pdi_feed_cache', $data, 10 * MINUTE_IN_SECONDS );
		return $data;
	}

	private function extract_products( array $feed ): array {
		if ( isset( $feed['data'] )  && is_array( $feed['data'] )  ) return $feed['data'];
		if ( isset( $feed['items'] ) && is_array( $feed['items'] ) ) return $feed['items'];
		if ( isset( $feed[0] ) ) return $feed;
		return [];
	}

	private function get_token() {
		$cached = get_transient( self::TOKEN_TRANSIENT );
		if ( $cached ) {
			return $cached;
		}

		$s        = $this->get_settings();
		$api_base = (string) ( $s['api_base'] ?? '' );
		$host     = wp_parse_url( $api_base, PHP_URL_HOST );

		$allowed_hosts = apply_filters( 'pdi_allowed_api_hosts', [
			'www.puckator-dropship.co.uk',
			'puckator-dropship.co.uk',
		] );
		if ( ! is_array( $allowed_hosts ) || ! in_array( $host, $allowed_hosts, true ) ) {
			return false;
		}

		$url = untrailingslashit( $api_base ) . '/rest/all/V1/integration/customer/token';

		if ( stripos( $url, 'https://' ) !== 0 ) {
			return false;
		}

		$username = (string) ( $s['username'] ?? '' );
		$password = (string) ( $s['password'] ?? '' );

		if ( $username === '' || $password === '' ) {
			return false;
		}

		$res = wp_safe_remote_post( $url, [
			'headers' => [
				'Content-Type' => 'application/json',
				'Accept'       => 'application/json',
			],
			'body'                => wp_json_encode( [ 'username' => $username, 'password' => $password ] ),
			'timeout'             => 30,
			'redirection'         => 3,
			'reject_unsafe_urls'  => true,
			'limit_response_size' => 256 * 1024,
		] );

		if ( is_wp_error( $res ) ) {
			return false;
		}

		if ( (int) wp_remote_retrieve_response_code( $res ) !== 200 ) {
			return false;
		}

		$body  = (string) wp_remote_retrieve_body( $res );
		$data  = json_decode( $body, true );
		$token = is_string( $data ) ? $data : ( $data['token'] ?? trim( $body, "\" \r\n" ) );

		if ( ! $token ) {
			return false;
		}

		set_transient( self::TOKEN_TRANSIENT, $token, 45 * MINUTE_IN_SECONDS );
		return $token;
	}

	private function extract_stock( array $p ): int {
		$s = $this->get_settings();

		if ( ! empty( $s['stock_field_path'] ) ) {
			$val = $this->get_by_path( $p, $s['stock_field_path'] );
			if ( is_numeric( $val ) ) return (int) $val;
		}

		foreach ( [ 'qty', 'stock', 'stock_qty', 'quantity', 'qty_available', 'available' ] as $k ) {
			if ( isset( $p[ $k ] ) && is_numeric( $p[ $k ] ) ) return (int) $p[ $k ];
		}

		$found = $this->find_numeric_key_recursive( $p, [ 'qty', 'stock', 'quantity' ] );
		if ( $found !== null ) return (int) $found;

		foreach ( [ 'in_stock', 'is_in_stock', 'stock_status' ] as $k ) {
			$val = $this->get_by_path( $p, $k );
			if ( is_bool( $val ) ) return $val ? 1 : 0;
			if ( is_string( $val ) ) {
				$vl = strtolower( $val );
				if ( in_array( $vl, [ 'in_stock', 'instock', 'yes', 'true', '1' ], true ) ) return 1;
				if ( in_array( $vl, [ 'out_of_stock', 'outofstock', 'no', 'false', '0' ], true ) ) return 0;
			}
		}

		return 0;
	}

	private function find_numeric_key_recursive( $array, $keywords ) {
		foreach ( $array as $key => $value ) {
			if ( is_array( $value ) ) {
				$result = $this->find_numeric_key_recursive( $value, $keywords );
				if ( $result !== null ) return $result;
			} else {
				foreach ( $keywords as $word ) {
					if ( stripos( (string) $key, $word ) !== false && is_numeric( $value ) ) return $value;
				}
			}
		}
		return null;
	}

	private function extract_price( array $p ): float {
		$s    = $this->get_settings();
		$keys = [];
		if ( ! empty( $s['price_field_key'] ) ) $keys[] = $s['price_field_key'];
		$keys = array_merge( $keys, [ 'price', 'cost', 'price_ex_vat', 'price_inc_vat', 'base_price', 'supplier_price' ] );
		foreach ( $keys as $k ) {
			$val = $this->get_by_path( $p, $k );
			if ( is_numeric( $val ) ) return (float) $val;
		}
		return 0.0;
	}

	private function extract_weight( array $p ): float {
		foreach ( [ 'weight', 'package_weight', 'product_weight', 'shipping_weight', 'extension_attributes.weight' ] as $k ) {
			$val = $this->get_by_path( $p, $k );
			if ( is_numeric( $val ) ) return (float) $val;
		}
		return 0.0;
	}

	private function get_shipping_for_weight( float $weight ): float {
		$s     = $this->get_settings();
		$table = json_decode( $s['shipping_table'] ?? '', true );

		if ( ! is_array( $table ) || empty( $table ) ) {
			return 0.00;
		}

		$table = array_values( array_filter( array_map( function( $row ) {
			$min  = isset( $row['min'] )  ? (float) $row['min']  : 0.0;
			$max  = isset( $row['max'] )  ? (float) $row['max']  : 0.0;
			$cost = isset( $row['cost'] ) ? (float) $row['cost'] : 0.0;
			$min  = max( 0.0, $min );
			$max  = max( $min, $max );
			$cost = max( 0.0, $cost );
			return [ 'min' => $min, 'max' => $max, 'cost' => $cost ];
		}, $table ) ) );

		foreach ( $table as $row ) {
			$min  = (float) ( $row['min']  ?? 0 );
			$max  = (float) ( $row['max']  ?? 0 );
			$cost = (float) ( $row['cost'] ?? 0 );
			if ( $weight >= $min && $weight <= $max ) {
				return $cost;
			}
		}

		$last = end( $table );
		return isset( $last['cost'] ) ? (float) $last['cost'] : 0.00;
	}

	private function fuzzy_filter( array $products, string $kw, bool $sku_only ): array {
		if ( count( $products ) > 5000 ) {
			$products = array_slice( $products, 0, 5000 );
		}

		$kw_norm = $this->norm( $kw );

		if ( $sku_only ) {
			$exact = strtolower( trim( $kw_norm ) );
			$out   = [];

			foreach ( $products as $p ) {
				$sku = strtolower( trim( (string) ( $p['sku'] ?? '' ) ) );
				if ( $sku !== '' && $sku === $exact ) {
					$out[] = $p;
				}
			}

			return $out;
		}

		$threshold = 0.30;
		$scored    = [];

		foreach ( $products as $p ) {
			$fields = [
				$p['name'] ?? '',
				$p['title'] ?? '',
				$p['sku'] ?? '',
				$p['description'] ?? '',
			];

			$hay = implode( ' ', array_map( 'trim', array_filter( $fields ) ) );
			$score = $this->fuzzy_score_adv( $hay, $kw );

			if ( $score >= $threshold ) {
				$scored[] = [
					'score' => $score,
					'p'     => $p,
				];
			}
		}

		usort(
			$scored,
			static function( $a, $b ) {
				return $b['score'] <=> $a['score'];
			}
		);

		return array_map(
			static function( $entry ) {
				return $entry['p'];
			},
			$scored
		);
	}

	private function norm( $s ): string {
		$s = strtolower( (string) $s );
		if ( function_exists( 'transliterator_transliterate' ) ) {
			$s = transliterator_transliterate( 'Any-Latin; Latin-ASCII', $s );
		}
		$s = preg_replace( '/[^a-z0-9\s]/', ' ', $s );
		$s = preg_replace( '/\s+/', ' ', $s );
		return trim( $s );
	}

	private function tokens( $s ): array {
		$n = $this->norm( $s );
		return $n ? array_values( array_filter( explode( ' ', $n ) ) ) : [];
	}

	private function trigrams( string $s ): array {
		$s = '  ' . $s . '  ';
		$out = [];
		for ( $i = 0; $i < strlen( $s ) - 2; $i++ ) $out[] = substr( $s, $i, 3 );
		return array_values( array_unique( $out ) );
	}

	private function fuzzy_score_adv( string $hay, string $q ): float {
		$h = $this->norm( $hay );
		$q = $this->norm( $q );

		if ( $h === '' || $q === '' ) {
			return 0.0;
		}

		if ( strpos( $h, $q ) !== false ) {
			return 1.0;
		}

		$ht = $this->tokens( $h );
		$qt = $this->tokens( $q );

		if ( empty( $ht ) || empty( $qt ) ) {
			return 0.0;
		}

		$covered = 0;
		foreach ( $qt as $qtok ) {
			$hit = false;
			foreach ( $ht as $htok ) {
				if ( $htok === $qtok || strpos( $htok, $qtok ) !== false ) {
					$hit = true;
					break;
				}
				$dist = levenshtein( $htok, $qtok );
				$len  = max( strlen( $qtok ), 1 );
				if ( $dist <= ceil( $len / 4 ) ) {
					$hit = true;
					break;
				}
			}
			if ( $hit ) {
				$covered++;
			}
		}

		$coverage = count( $qt ) ? ( $covered / count( $qt ) ) : 0.0;

		$Hg = $this->trigrams( $h );
		$Qg = $this->trigrams( $q );

		$inter = array_intersect( $Hg, $Qg );
		$union = array_unique( array_merge( $Hg, $Qg ) );

		$tri = count( $union ) > 0 ? count( $inter ) / count( $union ) : 0.0;

		$partial_hits = 0;
		foreach ( $qt as $word ) {
			foreach ( $ht as $hword ) {
				if ( substr_count( $hword, $word ) > 0 ) {
					$partial_hits++;
					break;
				}
			}
		}
		$partial_score = count( $qt ) ? min( 1.0, $partial_hits / count( $qt ) ) : 0.0;

		$score = ( 0.55 * $coverage ) + ( 0.30 * $tri ) + ( 0.15 * $partial_score );

		return max( 0.0, min( 1.0, $score ) );
	}

	private function encrypt_field( string $plain ): string {
		if ( $plain === '' ) return '';
		if ( ! defined( 'AUTH_KEY' ) || AUTH_KEY === '' ) return $plain;
		$key = hash( 'sha256', AUTH_KEY, true );
		$iv  = random_bytes( openssl_cipher_iv_length( 'AES-256-CBC' ) );
		$cipher = openssl_encrypt( $plain, 'AES-256-CBC', $key, OPENSSL_RAW_DATA, $iv );
		if ( ! $cipher ) return '';
		return base64_encode( $iv . $cipher );
	}

	private function decrypt_field( string $encoded ): string {
		if ( $encoded === '' ) return '';
		if ( ! defined( 'AUTH_KEY' ) || AUTH_KEY === '' ) return $encoded;
		$data = base64_decode( $encoded, true );
		if ( ! $data || strlen( $data ) < 16 ) return '';
		$key  = hash( 'sha256', AUTH_KEY, true );
		$ivlen = openssl_cipher_iv_length( 'AES-256-CBC' );
		if ( strlen( $data ) < $ivlen ) return '';
		$iv  = substr( $data, 0, $ivlen );
		$cipher = substr( $data, $ivlen );
		$plain = openssl_decrypt( $cipher, 'AES-256-CBC', $key, OPENSSL_RAW_DATA, $iv );
		return is_string( $plain ) ? $plain : '';
	}

	private function nf( $v ) { 
		$val = floatval( str_replace( ',', '.', (string) $v ) ); 
		return number_format( $val, 2, '.', '' ); 
	}

	private function get_settings(): array {
		$defaults = [
			'api_base'        => 'https://www.puckator-dropship.co.uk',
			'endpoint'        => self::DEFAULT_ENDPOINT,
			'username'        => '',
			'password'        => '',
			'vat'             => '20.00',
			'paypal_percent'  => '2.90',
			'paypal_fixed'    => '0.30',
			'profit_percent'  => '20.00',
			'stock_field_path'=> '',
			'price_field_key' => '',
			'shipping_table'  => '[{"min":0,"max":0.1,"cost":2.49},{"min":0.1,"max":1,"cost":3.99},{"min":1,"max":1.5,"cost":4.99},{"min":1.5,"max":2,"cost":5.99}]',
		];
		$s = get_option( self::OPT_SETTINGS, [] );
		$s = wp_parse_args( $s, $defaults );
		foreach ( [ 'vat', 'paypal_percent', 'paypal_fixed', 'profit_percent' ] as $k ) {
			$s[ $k ] = $this->nf( $s[ $k ] );
		}
		if ( ! empty( $s['password'] ) ) {
			$dec = $this->decrypt_field( $s['password'] );
			if ( $dec !== '' ) $s['password'] = $dec;
		}
		return $s;
	}

	public static function uninstall() {
		delete_option( self::OPT_SETTINGS );
		delete_option( self::OPT_LOGS );
		delete_option( self::OPT_SECURITY_LOGS );
		delete_transient( self::TOKEN_TRANSIENT );
		delete_transient( self::CACHE_VERSION_TRANSIENT );
		delete_transient( 'pdi_feed_cache' );
	}

	private function log( string $action, array $data = [] ) {
		$safe_data = json_decode( wp_json_encode( $data ), true );
		$encoded   = wp_json_encode( $safe_data );
		if ( strlen( (string) $encoded ) > 100000 ) {
			$safe_data = [ 'note' => 'Log entry truncated' ];
		}

		$logs = get_option( self::OPT_LOGS, [] );
		if ( ! is_array( $logs ) ) {
			$logs = [];
		}
		
		if ( isset( $safe_data['password'] ) ) {
			$safe_data['password'] = '[REDACTED]';
		}
		if ( isset( $safe_data['token'] ) ) {
			$safe_data['token'] = '[REDACTED]';
		}
		
		array_walk_recursive( $safe_data, function( &$value, $key ) {
			$sensitive_keys = [ 'password', 'token', 'api_key', 'secret', 'auth' ];
			if ( in_array( strtolower( $key ), array_map( 'strtolower', $sensitive_keys ), true ) ) {
				$value = '[REDACTED]';
			}
		});
		
		$logs[] = [
			'ts'     => time(),
			'action' => sanitize_text_field( $action ),
			'data'   => $safe_data,
		];
		if ( count( $logs ) > self::LOG_CAP ) {
			$logs = array_slice( $logs, - self::LOG_CAP );
		}
		update_option( self::OPT_LOGS, $logs, false );
	}
}

register_uninstall_hook( __FILE__, [ 'PDI_Plugin', 'uninstall' ] );
PDI_Plugin::instance();