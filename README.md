# PnP-IdentityModel

This repository holds code related to authentication in SharePoint.

##SharePointPnP.IdentityModel.Extensions
Originally, Microsoft.IdentityModel.Extensions.dll is where the code for SharePoint provider-hosted apps OAuth and S2S token processing is located. Microsoft.IdentityModel.Extensions is not maintained by anyone, but SharePoint add-ins, SharePointPnP.Core and a few other things depend on it. SharePointPnP.IdentityModel.Extensions is a port of that library created by the PnP team. We reference it in OfficeDevPnP.Core (and all other supporting solutions) instead of depending on Microsoft.IdentityModel.Extensions.
