# kong

```sh
curl -Lo kong-2.4.1.amd64.rpm $( rpm --eval "https://download.konghq.com/gateway-2.x-centos-%{centos_ver}/Packages/k/kong-2.4.1.el%{centos_ver}.amd64.rpm")
```

```text
_format_version: '2.1'
_transform: true
services:
  - host: 127.0.0.1
    name: _deploy_version_service
    path: /version
    routes:
      - methods:
          - GET
        name: _deploy_version_route
        paths:
          - /_deploy_version
        plugins:
          - name: pre-function
            enabled: true
            config:
              access:
                - kong.response.exit(200, '00000')
            protocols:
              - http
            tags:
              - kong
        strip_path: true
    tags:
      - kong
```

```sh
echo '' > /etc/kong/kong.conf
echo 'database = off' >> /etc/kong/kong.conf
echo 'declarative_config = /etc/kong/kong.yaml' >> /etc/kong/kong.conf
echo 'admin_listen = 0.0.0.0:8001, 0.0.0.0:8444 ssl' >> /etc/kong/kong.conf
echo 'proxy_listen = 0.0.0.0:8000, 0.0.0.0:8443 ssl' >> /etc/kong/kong.conf
```


