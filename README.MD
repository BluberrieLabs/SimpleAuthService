# SimpleAuthService

SimpleAuthService is designed to be a lightweight user management component for microservice architectures.

SimpleAuthService provides a [REST API](https://bluberrielabs.github.io/SimpleAuthService/) to allow users to create and log into accounts, exchanging login credentials (username/password or Facebook tokens) for [JSON Web Tokens](https://jwt.io).

User passwords are hashed using PBKDF2 with SHA512 before storage.

## Deployment

SimpleAuthService requires Tomcat (or similar servlet engine) and optionally a database. There are several ways to deploy the software. 

### Docker

The easiest way to run the software is using the preconfigured docker image. 

`docker pull bluberrieio/simpleauthservice:latest`

Once downloaded, configure the sas.properties file (see next section) and JWT signing certificates and place them in a folder that is mounted at /etc/sas in the docker image. The Docker container used a MySQL database backend, the configuration details of which are given in the [example sas.properties file](https://github.com/BluberrieLabs/SimpleAuthService/blob/master/docs/sas.\
properties.example), and which should not be changed. 

For instance, if you place the files in /home/user/sas, you could run SimpleAuthService with the command: 

`docker run -v /home/user/sas:/etc/sas -p 127.0.0.1:8080:8080 -i -t bluberrieio/simpleauthservice`

You can then get the openapi.json specification document to check the service is running with:

`curl http://localhost:8080/sas/v1/swagger.json`

### Binary

To deploy the war file to the Java servlet container of your choice. By default, it will use an on disk h2 database. If you would like to use a different RDBMS such as MySQL, create an empty database and user and configure the details in `sas.properties`. See the next section for more details. 

### Building from source

You can build the war file yourself from the latest sourcecode using maven with `mvn compile war:war`.

## Configuration

The service is configured via a Java properties file named `sas.properties`, read from one of the following locations:

* `/etc/sas/sas.properties`
* `$HOME/.sas/sas.properties`

An example sas.properties file can be found in the [docs](https://github.com/BluberrieLabs/SimpleAuthService/blob/master/docs/sas.properties.example) folder. 

The following properties should be set to configured the service:

* `redirecturl` - the URL email confirmations are redirected to (default value="https://www.google.com")
* `sas-user` - the preset admin username (default value="admin@foo.com")
* `sas-passwd` - the preset admin password (default value="changeme")
* `apikey` - key used to secure API operations (default value="1234567")
* `jwt-audience` - the audience value contained in issued JWT tokens (default value="blahblah")
* `jwt-lifetime` - lifetime of issued JWD tokens in miliseconds (default value="86400000")
* `jwt-web-lifetime` - lifetime of JWT tokens issued for web logins in miliseconds (default value="43200000")
* `pwd-reset-lifetime` - lifetime of password reset tokens in miliseconds (default value="3600000")
* `jwt-refresh-lifetime` - lifetime of JWT refresh token (default value="31536000000")
* `jwt-refresh-audience` - the audience value contained in issued JWT refresh tokens (default value="sas-renewer")
* `jwt-issuer` - the issuer value contained in issued JWT tokens (default value="foo.bar.com")
* `facebook-id` - Facebook app ID for Facebook login
* `facebook-secret` - Facebook app secret for Facebook login
* `publickey` - path to public key used to sign JWT tokens
* `privatekey` - path to private key used to sign JWT tokens
* `serverurl` - URL of running service (e.g. https://localhost/sas/v1)
* `reseturl` - the URL of the page to visit to reset a forgotten password.

### Email

You can configure SimpleAuthService to send emails to send automated emails to users for the following:

1. To confirm their email address. When they click on the confirmation link, they are redirected to `redirecturl`.
2. When the address is confirmed, a welcome email is sent.
3. When the user requests to reset their password, a reset email is sent with a link to `reseturl`.

To configure email sending, the following SMTP server details must be set:

* `email-user` - username used to log on to SMTP server
* `email-password` - SMTP server password
* `mail.smtp.host` - SMTP server hostname
* `mail.smtp.starttls.enable` - SMTP server should use TLS (boolean)
* `mail.smtp.auth` - SMTP server requires auth (boolean)

### Database

By default, SimpleAuthService maintains the state of the service to a h2 database file on disk.

SimpleAuthService users [Hibernate](http://hibernate.org/orm/) to map persistent objects to database tables. You can change the backend database used by configuring the following hibernate properties in the sas.properties file:

* `hibernate.connection.driver_class` - database driver to use (default value="org.h2.Driver")
* `hibernate.connection.url` - URL of database to use (default value="jdbc:h2:file:/tmp/sas;DB_CLOSE_DELAY=-1;MVCC=TRU")
* `hibernate.connection.username` - database username (default value="sa")
* `hibernate.connection.password` - database password
* `hibernate.dialect` - SQL dialect to use (default value="org.hibernate.dialect.H2Dialect")

Adding other `hibernated.*` properties to sas.properties should allow you to override standard hibernate.cfg.xml properties. See the Hibernate documentation for more details.

### Certificates

To generate signed JWT tokens, SimpleAuthService requires the access to the public and private components of a digital certificate.

## API

A Swagger description of the API is available from the service. For example, if the service is deployed on localhost port 80, the Swagger document is available at http://localhost/sas/v1/swagger.json.

A full description of the API is available [here](https://bluberrielabs.github.io/SimpleAuthService/).

## Operational Notes

A login provides two credentials: a short-lived user JWT token and a longer lived renewal token. The renewal token can be used to renew the user token, without prompting the user for their login credentials.

The renewal token should be stored securely, in a mobile app keystore for example. When used for web logins, the renewal token is not supplied.

It is advisable to deploy the [SAS-UI](https://github.com/BluberrieLabs/SAS-UI) component to configure the service and manage users.

SimpleAuthService supports two user roles:
1. USER - for everyday users
2. ADMINISTRATOR - required to access the admin services.

The initial user account (configured in the sas.properties file) is given the ADMINISTRATOR role, and allowed to grant that role to other users.

## Limitations

Currently, the service can only generate tokens for a single JWT audience.

The tool is designed to be very lightweight and provide the minimum functionality required to run a mobile app or website where the backend is secured with JWT tokens. It does not implement a full OAuth or OpenID flow.

## Licence

(C) Copyright 2017-2018 Bluberrie Labs (http://bluberrie.io/).

Licensed under the Apache License, Version 2.0 (the "License"); you may not use this software except in compliance with the License. You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.

See the License for the specific language governing permissions and limitations under the License.
