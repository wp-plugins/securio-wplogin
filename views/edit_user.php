
<h3>Securio Multi-Factor Settings</h3>
<table class="form-table">
	<tbody>

		<tr>
			<th scope="row">Hide settings from user</th>
			<td>
				<div><input name="MFA_hidefromuser" id="MFA_hidefromuser"  class="tog" type="checkbox" <?=checked( $MFA_hidefromuser, 'enabled', false );?>  />
			</td>
		</tr>

		<tr>
			<th scope="row">Active</th>
			<td>
				<div><input name="MFA_enabled" id="MFA_enabled"  class="tog" type="checkbox" <?=checked( $MFA_enabled, 'enabled', false );?> />
			</td>
		</tr>

	</tbody>
</table>