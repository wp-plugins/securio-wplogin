<?php

	// Create URL for the Google charts QR code generator.
	$chl = urlencode( "otpauth://totp/{$MFA_description}?secret={$MFA_secret}" );
	$qrcodeurl = "https://chart.googleapis.com/chart?cht=qr&amp;chs=300x300&amp;chld=H|0&amp;chl={$chl}";

?>	

<style>
	.MFA_devices{
		display:none;
	}
</style>

<h3>Securio MultiFactor Authentication Settings</h3>

<table class="form-table">
<tbody>
	<tr>
		<th scope="row">Active</th>
		<td>
			<input name="MFA_enabled" id="MFA_enabled" class="tog" type="checkbox" <?=checked( $MFA_enabled, 'enabled', false );?> />
		</td>
	</tr>

	<?php if ( $is_profile_page || IS_PROFILE_PAGE ) { ?>

		<tr>
			<th scope="row">Multi-Factor Device Type</th>
			<td>
				<select name="MFA_device" id="MFA_device">
					<option value="totp">Google Authenticator</option>
					<option value="totp">Windows Phone "Authenticator"</option>
					<option value="totp">Securio MFA - TOTP</option>
					<option value="securio">Securio MFA - Hosted</option>
				</select>
			</td>
		</tr>

		<tr class="MFA_devices MFA_device_securio" >
			<th></th>
			<td>
				<span class="description">Settings for Securio MFA are managed in the plugin settings, and devices are managed in the Securio Portal.</span>
			</td>
		</tr>

		<tr class="MFA_devices MFA_device_totp" >
			<th scope="row">Relaxed mode</th>
			<td>
				<input name="MFA_relaxedmode" id="MFA_relaxedmode" class="tog" type="checkbox" <?= checked( $MFA_relaxedmode, 'enabled', false );?> />
				<span class="description">Use if Your blog and phone clocks seem out of sync ( Allows &#177;4 min)</span>
				<br />
				<span class="description">Current Time: <b><?= date('h:i a');?></b> (Ignore Timezone)</span>
			</td>
		</tr>
		
		<tr class="MFA_devices MFA_device_totp" >
			<th><label for="MFA_description">Description</label></th>
			<td>
				<input name="MFA_description" id="MFA_description" value="<?=$MFA_description;?>"  type="text" size="25" />
				<span class="description">Description that you'll see in <span class="MFA_device_name">Securio Multi-Factor app.</span> on your phone.</span>
				<br />
			</td>
		</tr>

		<tr class="MFA_devices MFA_device_totp" >
			<th><label for="MFA_secret">Secret</label></th>
			<td>
				<input name="MFA_secret" id="MFA_secret" value="<?=$MFA_secret;?>" readonly="readonly"  type="text" size="25" />
				<input name="MFA_newsecret" id="MFA_newsecret" value="Create new secret" type="button" class="button" />
				<input name="show_qr" id="show_qr" value="Show/Hide QR code"   type="button" class="button" onclick="jQuery('#MFA_QR_INFO').toggle('slow');" />
				<input name="show_qr" id="show_qr" value="Show/Hide Current OTP"   type="button" class="button" onclick="jQuery('#MFA_CURRENT_CODE').toggle('slow');" />
			</td>
		</tr>

		<tr class="MFA_devices MFA_device_totp" >
			<th></th>
			<td>
				<div id="MFA_QR_INFO" style="display: none" >
					<img id="MFA_QRCODE"  src="<?=$qrcodeurl;?>" alt="QR Code"/>
					<span class="description"><br/>Scan this with the <span class="MFA_device_name">Securio Multi-Factor app.</span></span>
				</div>
			</td>
		</tr>

		<tr class="MFA_devices MFA_device_totp" >
			<th></th>
			<td>
				<div id="MFA_CURRENT_CODE" style="display: none" >
					The OTP in <span class="MFA_device_name">Securio Multi-Factor app.</span> should be one of the following:
					<h3><?=implode(', ',$current_codes);?></h3>
					<span class="description">As of the load of this page at: <b><?= date('h:i a');?></b> (Ignore Timezone)</span>
				</div>
			</td>
		</tr>

		<tr>
			<th scope="row">Wordpress App password</th>
			<td>
				<input name="MFA_pwdenabled" id="MFA_pwdenabled" class="tog" type="checkbox" <?=checked( $MFA_pwdenabled, 'enabled', false );?> />
				<span class="description">Allowing the WordPress App <b>Override</b> password will decrease your overall login security</span>
			</td>
		</tr>
		
		<tr>
			<th>
				&nbsp;
			</th>
			<td>
				<input name="MFA_password" id="MFA_password" readonly="readonly" value="<?=$MFA_password;?>" type="text" size="25" />
				<input name="MFA_createpassword" id="MFA_createpassword" value="Create new password"   type="button" class="button" />
				<span class="description" id="MFA_passworddesc">Password is not stored in cleartext, this is your only chance to see it.</span>
			</td>
		</tr>
	<?php } ?>
	

	</tbody>
</table>
<script type="text/javascript">
	var SMFAnonce='<?=wp_create_nonce('SecurioMFAaction');?>';
	var pwdata;
	jQuery('#MFA_newsecret').bind('click', function() {
		var data=new Object();
		data['action']	= 'securio_mfa_action';
		data['nonce']	= SMFAnonce;
		jQuery.post(ajaxurl, data, function(response) {
				jQuery('#MFA_secret').val(response['new-secret']);
				chl=escape("otpauth://totp/"+jQuery('#MFA_description').val()+"?secret="+jQuery('#MFA_secret').val());
				qrcodeurl="https://chart.googleapis.com/chart?cht=qr&chs=300x300&chld=H|0&chl="+chl;
				jQuery('#MFA_QRCODE').attr('src',qrcodeurl);
				jQuery('#MFA_QR_INFO').show('slow');
			});  	
	});  

	jQuery('#MFA_description').bind('focus blur change keyup', function() {
			chl=escape("otpauth://totp/"+jQuery('#MFA_description').val()+"?secret="+jQuery('#MFA_secret').val());
			qrcodeurl="https://chart.googleapis.com/chart?cht=qr&chs=300x300&chld=H|0&chl="+chl;
			jQuery('#MFA_QRCODE').attr('src',qrcodeurl);
	});

	jQuery('#MFA_createpassword').bind('click',function() {
		var data=new Object();
		data['action']	= 'securio_mfa_action';
		data['nonce']	= SMFAnonce;
		data['save']	= 1;
		jQuery.post(ajaxurl, data, function(response) {
				jQuery('#MFA_password').val(response['new-secret'].match(new RegExp(".{0,4}","g")).join(' '));
				jQuery('#MFA_passworddesc').show();
			});  	
	});

	jQuery('#MFA_enabled').bind('change',function() {
		securio_mfa_apppasswordcontrol();
	});

	jQuery(document).ready(function() {
		jQuery('#MFA_passworddesc').hide();
		securio_mfa_apppasswordcontrol();
	});

	function securio_mfa_apppasswordcontrol() {
		if (jQuery('#MFA_enabled').is(':checked')) {
			jQuery('#MFA_pwdenabled').removeAttr('disabled');
			jQuery('#MFA_createpassword').removeAttr('disabled');
		} else {
			jQuery('#MFA_pwdenabled').removeAttr('checked')
			jQuery('#MFA_pwdenabled').attr('disabled', true);
			jQuery('#MFA_createpassword').attr('disabled', true);
		}
	}	


	jQuery('#MFA_device').bind('change',function() {
		securio_mfa_device_types();
	});
	function securio_mfa_device_types() {

		jQuery('.MFA_device_name').text( jQuery('#MFA_device :selected').text() );

		//Hide all
		jQuery('.MFA_devices').hide();

		// Show one
		if ( jQuery('#MFA_device').val() == 'totp' ) {
			jQuery('.MFA_device_totp').show();
		} else if ( jQuery('#MFA_device').val() == 'securio' ) {
			jQuery('.MFA_device_securio').show();
		}
	}
	securio_mfa_device_types();
</script>