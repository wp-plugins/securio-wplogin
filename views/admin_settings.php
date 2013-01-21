
<div class=wrap>
	<form method="post" action="<?= esc_attr($_SERVER["REQUEST_URI"]); ?>">
		<?php
		if ( function_exists('wp_nonce_field') )
			wp_nonce_field('login-ban_update-options');
		?>


		<h2>Securio WPLogin Settings</h2>

		
		<table class="form-table">

			<tr valign="top">
				<td colspan="2">
					<h3>Securio Multi-Factor Settings</h3>
				</td>
			</tr>

			<tr valign="top">
				<th scope="row"><label for="default_post_format">Multi-Factor Enabled</label></th>
				<td>
					<select name="MFA_enabled" id="MFA_enabled" style="width:300px;">
						<option value="enabled" <?= ( $Securio_WPLoginOptions['MFA_enabled']  )?"selected":""; ?> >Available for all users</option>
						<option value="disabled" <?= ( ! $Securio_WPLoginOptions['MFA_enabled'] )?"selected":""; ?> >Disabled across all Users</option>
					</select>
				</td>
			</tr>



			<tr valign="top">
				<td colspan="2">
					<h3>Securio Brute-Force Protection Settings</h3>
				</td>
			</tr>


			<tr valign="top">
				<th scope="row"><label for="default_post_format">Brute-Force Protection Enabled</label></th>
				<td>
					<select name="BF_enabled" id="BF_enabled" style="width:300px;">
						<option value="enabled" <?= ( $Securio_WPLoginOptions['BF_enabled']  )?"selected":""; ?> >Yes, Protect me from Brute-Force Logins</option>
						<option value="disabled" <?= ( ! $Securio_WPLoginOptions['BF_enabled'] )?"selected":""; ?> >No, do not limit failed attempts to Login</option>
					</select>
				</td>
			</tr>



			<tr valign="top">
				<th scope="row"><label for="BF_max_login_retries">Failed logins before Banning?</label></th>
				<td>
					<input name="BF_max_login_retries" type="text" id="BF_max_login_retries"  size="8"  value="<?= esc_attr($Securio_WPLoginOptions['max_login_retries']); ?>" class="regular-text code" />

				</td>
			</tr>

			<tr valign="top">
				<th scope="row"><label for="BF_retries_within">Time Window for failed logins</label></th>
				<td>
					<input name="BF_retries_within" type="text" id="BF_retries_within"  size="8"  value="<?= esc_attr($Securio_WPLoginOptions['retries_within']); ?>" class="regular-text code" />
					 (minutes)
					 <br />
					 ie. 5 failed logins withn X minutes
				</td>
			</tr>

			<tr valign="top">
				<th scope="row"><label for="BF_lockout_length">Lockout Length</label></th>
				<td>
					<input name="BF_lockout_length" type="text" id="BF_lockout_length"  size="8"  value="<?= esc_attr($Securio_WPLoginOptions['lockout_length']); ?>" class="regular-text code" />
					 (minutes)
					 <br />
					 How long the IP is banned for
				</td>
			</tr>

			<tr valign="top">
				<th scope="row"><label for="BF_ban_invalid_usernames">Ban Invalid Usernames?</label></th>
				<td>
					<input type="radio" name="BF_ban_invalid_usernames" value="enabled" <?= ( $Securio_WPLoginOptions['ban_invalid_usernames'] )?"checked":""; ?> /> Yes, count invalid usernames as well as failed passwords
					<br />
					<input type="radio" name="BF_ban_invalid_usernames" value="disabled" <?= ( ! $Securio_WPLoginOptions['ban_invalid_usernames'] )?"checked":""; ?>> No. dont keep track of invalid usernames
				</td>
			</tr>

			<tr valign="top">
				<th scope="row"><label for="BF_mask_login_errors">Mask Login Errors?</label></th>
				<td>
					<input type="radio" name="BF_mask_login_errors" value="enabled" <?= ( $Securio_WPLoginOptions['mask_login_errors'] )?"checked":""; ?> /> Yes, best for security
					<br />
					<input type="radio" name="BF_mask_login_errors" value="disabled" <?= ( ! $Securio_WPLoginOptions['mask_login_errors'] )?"checked":""; ?>> No, show username / password error 
				</td>
			</tr>

			<tr valign="top">
				<th scope="row"><label for="BF_trust_proxy">Allow Proxy forwarded IP</label></th>
				<td>
					<input type="radio" name="BF_trust_proxy" value="enabled" <?= ( $Securio_WPLoginOptions['trust_proxy'] )?"checked":""; ?> /> Allowed, (must specify IPs of trusted Proxies)
					<br />
					<input type="radio" name="BF_trust_proxy" value="disabled" <?= ( ! $Securio_WPLoginOptions['trust_proxy'] )?"checked":""; ?>> NOT Allowed
					<br />
					<input type="radio" name="BF_trust_proxy" value="disabled" > I dont know
				</td>
			</tr>

			<tr valign="top"  class="proxy_related" style="display:none;">
				<th scope="row"><label for="BF_trusted_proxy_header">Proxy Header Field</label></th>
				<td>
					<input type="text" name="BF_trusted_proxy_header" size="8" value="<?= esc_attr($Securio_WPLoginOptions['trusted_proxy_header']); ?>" style="width:200px;" />
				</td>
			</tr>

			<tr valign="top"  class="proxy_related" style="display:none;">
				<th scope="row"><label for="BF_mask_login_errors">Trusted Proxy IPs (comma seperated)</label></th>
				<td>
					<input type="text" name="BF_trusted_proxy_ips" size="8" value="<?= esc_attr($Securio_WPLoginOptions['trusted_proxy_ips']); ?>" style="width:200px;" />
				</td>
			</tr>
		</table>


		<div class="submit">
			<input type="submit" name="update_securiowploginSettings" value="Update Settings" />
		</div>
		
	</form>
		
	<br />
	
	<form method="post" action="<?= esc_attr($_SERVER["REQUEST_URI"]); ?>">
		<?php
		if ( function_exists('wp_nonce_field') )
			wp_nonce_field('login-ban_release-securio_auth_bans');
		?>
		<h4>Currently Locked Out</h4>
		
		<?php
			$num_lockedout = count($list_of_banned);
			if( 0 == $num_lockedout ) {
				echo "<p>No current IP blocks locked out.</p>";
			} else {
				foreach ( $list_of_banned as $key => $option ) {
					?>
						<li>
							<input type="checkbox" name="releaseme[]" value="<?= esc_attr($option['id']); ?>"> 
							<?= esc_attr($option['user_ip']); ?> (<?= esc_attr($option['minutes_left']); ?> minutes left)
						</li>
					<?php
				}
			}
		?>
		<div class="submit">
		<input type="submit" name="release_securio_auth_bans" value="Release Selected" /></div>
	</form>
</div>
<script type="text/javascript">

	jQuery('input[name=BF_trust_proxy]').bind('change',function() {
		SecurioBF_enableproxy();
	});

	function SecurioBF_enableproxy() {
		if( jQuery('input[name=BF_trust_proxy]:radio:checked').val() == 'enabled' ){
			jQuery('.proxy_related').show();
		} else {
			jQuery('.proxy_related').hide();
		}
	}
	SecurioBF_enableproxy();
</script>