vault secrets enable transit

vault write transit/keys/Order-Aes256GcmIv96Tag128 \
	type=aes256-gcm96 \
	exportable=true \
	auto_rotate_period=90d