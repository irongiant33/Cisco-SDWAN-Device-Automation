# get JWT, CSRF, and refresh token. 1800 is max duration.
curl --insecure -X POST "https://<IP>/jwt/login" -H "Content-Type: application/json" -d "{"username": "","password": "", "duration": "1800"}"

# issue post request with JWT and CSRF token
curl -X GET "https://<IP>/dataservice/device" -H "Content-Type: application/json" -H "Authorization: Bearer <JWT Token>" -H "X-XSRF-TOKEN: <CSRF "<CSRF Token>" -k

# get list of devices
curl --insecure -X GET "https://<IP>/dataservice/device" -H "Content-Type: application/json" -H "Authorization: Bearer <JWT>" -H "X-XSRF-TOKEN: <CSRF>"