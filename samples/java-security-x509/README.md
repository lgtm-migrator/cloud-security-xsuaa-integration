# Description
The 2 samples in this directory [consumer-x509](https://github.com/SAP/cloud-security-xsuaa-integration/tree/x509-app2service/samples/java-security-x509/consumer-x509) and [provider-x509](https://github.com/SAP/cloud-security-xsuaa-integration/tree/x509-app2service/samples/java-security-x509/provider-x509) are used to demonstrate application to service communication scenario over mutual TLS using X509 certificate.

## provider-x509 
This application is exposed as reusable service that is made available via [SAP BTP Service Manager](https://help.sap.com/viewer/09cc82baadc542a688176dce601398de/Cloud/en-US/3a27b85a47fc4dff99184dd5bf181e14.html) and can be reused by consumer application in this case: `consumer-x509`.

It consists of:
- provider service broker (`provider-service-broker` IAS instance)
- provider service (`provider-x509` application)
- provider service instance (`provider-x509-instance` reusable service from service catalog)

## consumer-x509
This application consumes the exposed reusable service by calling it over mutual TLS with X509 certifacte

It consists of:
- consumer application (`consumer-x509` application)
- consumer IAS instance (`consumer-ias` IAS instance)

## Setup
1. Start with the provider side setup. Follow steps in [provider-x509 readme](https://github.com/SAP/cloud-security-xsuaa-integration/blob/x509-app2service/samples/java-security-x509/provider-x509/README.md)
2. Finish off with consumer side setup by following steps in [consumer-x509 readme](https://github.com/SAP/cloud-security-xsuaa-integration/blob/x509-app2service/samples/java-security-x509/consumer-x509/README.md)
