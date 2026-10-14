## Default Permission

Lets the HumID UI read a passport or ID card chip: check for a reader, open a session, exchange APDUs, end it.

#### This default permission set includes the following:

- `allow-probe`
- `allow-begin`
- `allow-transceive`
- `allow-message`
- `allow-end`

## Permission Table

<table>
<tr>
<th>Identifier</th>
<th>Description</th>
</tr>


<tr>
<td>

`humid-nfc:allow-begin`

</td>
<td>

Enables the begin command without any pre-configured scope.

</td>
</tr>

<tr>
<td>

`humid-nfc:deny-begin`

</td>
<td>

Denies the begin command without any pre-configured scope.

</td>
</tr>

<tr>
<td>

`humid-nfc:allow-end`

</td>
<td>

Enables the end command without any pre-configured scope.

</td>
</tr>

<tr>
<td>

`humid-nfc:deny-end`

</td>
<td>

Denies the end command without any pre-configured scope.

</td>
</tr>

<tr>
<td>

`humid-nfc:allow-message`

</td>
<td>

Enables the message command without any pre-configured scope.

</td>
</tr>

<tr>
<td>

`humid-nfc:deny-message`

</td>
<td>

Denies the message command without any pre-configured scope.

</td>
</tr>

<tr>
<td>

`humid-nfc:allow-probe`

</td>
<td>

Enables the probe command without any pre-configured scope.

</td>
</tr>

<tr>
<td>

`humid-nfc:deny-probe`

</td>
<td>

Denies the probe command without any pre-configured scope.

</td>
</tr>

<tr>
<td>

`humid-nfc:allow-transceive`

</td>
<td>

Enables the transceive command without any pre-configured scope.

</td>
</tr>

<tr>
<td>

`humid-nfc:deny-transceive`

</td>
<td>

Denies the transceive command without any pre-configured scope.

</td>
</tr>
</table>
