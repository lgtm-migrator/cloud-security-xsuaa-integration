# Description
This sample is a Java back-end consumer application running on the Cloud Foundry that consumes by [Service Manager](https://help.sap.com/viewer/09cc82baadc542a688176dce601398de/Cloud/en-US/3a27b85a47fc4dff99184dd5bf181e14.html) exposed reusable service via mTLS. For all incoming requests it checks whether the user is authorized using the 
[`IasTokenAuthenticator`](https://github.com/SAP/cloud-security-xsuaa-integration/blob/x509-app2service/java-security/src/main/java/com/sap/cloud/security/servlet/IasTokenAuthenticator.java) which is defined in the [Java Security](https://github.com/SAP/cloud-security-xsuaa-integration/tree/x509-app2service/java-security) library. Then request is forwarded to provider-service via mTLS.

# Deployment on Cloud Foundry
To deploy the application, the following steps are required:
- Compile the Java application
- Create an IAS service instance
- Configure the manifest
- Deploy the application    
- Bind provider-service-x509-instance and consumer-ias to the application
- Access the application

Previously provider application should be set up as per the [read me](../provider-x509/README.md).

## Compile the Java application
Run maven to package the application
```shell
mvn clean package
```

## Create the IAS service instance
Create an IAS service instance defining `consumed-services` configuration with exposed service `provider-service-x509` from service catalog.
```shell
cf create-service identity application consumer-ias -c '{"consumed-services": [{"service-instance-name": "provider-service-x509"}],"xsuaa-cross-consumption": true,"display-name" : "consumer-ias","multi-tenant":true}'
```

## Configure the manifest
The [vars](../../vars.yml) contains hosts and paths that need to be adopted.

## Deploy the application
Deploy the application using cf push. It will expect 1 GB of free memory quota.

```shell
cf push --vars-file ../vars.yml
```

## Bind consumer-x509 application
- Bind application with `consumer-ias` instance
```shell script
cf bind-service consumer-x509 consumer-ias -c '{"credential-type": "X509_GENERATED"}'
```
- Bind the exposed reusable service with the application to get the service URL in system environment variable `VCAP_SERVICES`
```shell script
cf bind-service consumer-x509 provider-service-x509-instance
```
## Access the application using IAS token
- Access credentials configuration(i.e. `clientid`, `clientsecret`, `certificate`, `key`) from system environment variable `VCAP_SERVICES.identity.credentials`. You can get them using `cf env consumer-x509`. 
- Get an access token via `curl`. Make sure you replace the placeholders `clientid`, `clientsecret` and `url` (without `https://` !!!) 

```
curl -X POST \
  https://<<clientid>>:<<clientsecret>>@<<url>>/oauth2/token \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -d 'grant_type=password&username=<<your ias user>>&password=<<your ias password>>'
```
- Copy the `id_token` into your clipboard.
- Access the app via `curl`. Don't forget to fill the placeholders.
```shell script
curl -X GET https://consumer-x509-((ID)).((LANDSCAPE_APPS_DOMAIN))/hello-x509 -H 'Authorization: Bearer <<your id_token>>'
```

If `provider-service-x509` could be accessed by consumer application `consumer-x509` you should see something like this:
:smile:

## Clean-Up
Finally delete your application and your service instances using the following commands:
```
cf us consumer-x509 consumer-ias
cf us consumer-x509 provider-service-x509-instance
cf delete -f consumer-x509
cf delete-service -f consumer-ias
```
