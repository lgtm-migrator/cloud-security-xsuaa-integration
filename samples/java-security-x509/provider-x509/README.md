# Description
This sample is a Java back-end application running on the Cloud Foundry as a (reuse) service provider. For all incoming requests it checks whether the user is authenticated using the 
[`IasTokenAuthenticator`](https://github.com/SAP/cloud-security-xsuaa-integration/blob/x509-app2service/java-security/src/main/java/com/sap/cloud/security/servlet/IasTokenAuthenticator.java) which is defined in the [java security](/java-security) library and it validates X509 certificate from the incoming request.

# Deployment on Cloud Foundry
To deploy the application, the following steps are required:
- Compile the Java application
- Configure the manifest
- Deploy the application    
- Create an IAS service instance
- Bind service instance to application using X509
- Access the application
- Expose application as reusable service in Service Manager

## Compile the Java application
Run maven to package the application
```shell
mvn clean package
```

## Configure the manifest
The [vars](../../vars.yml) contains hosts and paths that need to be adopted.

## Deploy the application
Deploy the application using cf push. It will expect 1 GB of free memory quota.

```shell
cf push --vars-file ../vars.yml
```

## Create the IAS service instance
Use the IAS service broker capability by providing service catalog in configuration and create a new service instance.
```shell script
cf create-service identity application service-provider-broker -c '{
"xsuaa-cross-consumption":true,
"display-name":"provider-service--x509-broker",
"catalog":{
"services":[{
"name":"provider-service-x509",
"plans":[{
    "name": "reuse-plan",
    "bindable": true,
    "metadata": {
        "bindingData": {
            "url": "https://provider-service-x509-((ID)).cert.((LANDSCAPE_APPS_DOMAIN))"
        }
    }
}]}]},
"multi-tenant":true
}'
```

## Bind the IAS service instance with provider application using X509
```shell script
cf bind-service provider-service-x509 service-provider-broker -c '{"credential-type": "X509_GENERATED"}'
```
You might need to restart application to get the new binding data in `VCAP_SERVICES` system environment variable.
```shell script
cf restage provider-service-x509
```

## Access the application
- Access credentials configuration(i.e. `clientid`, `clientsecret`, `certificate`, `key`) from system environment variable `VCAP_SERVICES.identity.credentials`. You can get them using `cf env provider-service-x509`. 
- Get an access token via `curl`. Make sure you replace the placeholders `clientid`, `clientsecret` and `url` (without `https://` !!!) 

```
curl -X POST \
  https://<<clientid>>:<<clientsecret>>@<<url>>/oauth2/token \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -d 'grant_type=password&username=<<your ias user>>&password=<<your ias password>>'
```
- Copy the `id_token` into your clipboard.
- Get X509 certificate and key from system environment variable `VCAP_SERVICES.identity.credentials` and store them in separate files with `*.pem` extension
- Access the app via `curl`. Don't forget to fill the placeholders.
```shell script
curl --cert cert.pem --key key.pem -X POST https://provider-service-x509-<<ID>>.cert.<<LANDSCAPE_APPS_DOMAIN>>/hello-x509 -H 'Authorization: Bearer <<your id_token>>'
```

You should see something like this:
```
You ('<your email>') can access provider service with x509.
```
- If you call the same endpoint without `Authorization` header you should get a `401`.

# Expose your application as a reusable service in Service Manager
- Get the CLI tool `smctl`, if you don't have it from 
[SMCTL GitHub](https://wiki.wdf.sap.corp/wiki/display/PFS/How+to+register+a+subaccount-scoped+service+broker)
## Login to smctl 
Make sure you have a subaccount in which you are a security administrator. Don't forget to replace placeholders.
```shell script
smctl login -a https://service-manager.cfapps.<<LANDSCAPE_APPS_DOMAIN>> --param subdomain=<<YOUR SUBDOMAIN>>
```
## Expose your application as a service
- You need to use X509 `certificate`, `key` and `osb_url` from the service-provider-broker service key to fill in the placeholders. 
```shell script
smctl curl -X POST /v1/service_brokers -d '{"name": "provider-service-x509", "broker_url": "<<osb_url>>", "credentials": {"tls": { "client_certificate": "<<YOUR X509 CERTIFICATE>>", "client_key": "<<YOUR X509 KEY>>"}}}'
```

- Check the service catalog. You can see if your application is exposed as reusable service by calling /v2/catalog for`osb_url` endpoint.
```shell script
curl --cert cert.pem --key key.pem -X GET https://<<osb_url>>/v2/catalog
```
You should be able to see your service in the service catalog. Now you can create an instance of this reusable service that can be consumed by the consumer application.
```shell script
cf create-service provider-service-x509 reuse-plan provider-service-x509-instance
```

More information about registering service in Service Manager can be found [here](https://wiki.wdf.sap.corp/wiki/display/PFS/How+to+register+a+subaccount-scoped+service+broker)

Proceed with consumer application setup by following steps in the [consumer-x509 readme](../consumer-x509/README.md)

## Clean-Up
Finally, delete your application and your service instances using the following commands:
```
cf us provider-service-x509 service-provider-broker
cf delete -f provider-service-x509
cf delete-service -f service-provider-broker
smctl delete-broker provider-service-x509broker-<<subaccount ID>>
```

