﻿using RestSharp;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace timw255.Sitefinity.RestClient.ServiceWrappers.Ecommerce.Catalog
{
    public class ProductVariationsModuleServiceWrapper : ServiceWrapper
    {
        public ProductVariationsModuleServiceWrapper(SitefinityRestClient sf)
        {
            this.ServiceUrl = "Sitefinity/Services/Ecommerce/Catalog/ProductVariationsModuleService.svc/";
            this.SF = sf;
        }

        //[WebInvoke(Method = "POST", UriTemplate = "Set/SortOrder/{attributeId}/{sortOrder}/", ResponseFormat = WebMessageFormat.Xml)]
        public void SetListSortOrder(Guid attributeId, string sortOrder)
        {
            var request = new RestRequest(this.GetServiceUrl("Set/SortOrder/{attributeId}/{sortOrder}/"), Method.POST);

            request.AddUrlSegment("attributeId", attributeId.ToString());
            request.AddUrlSegment("sortOrder", sortOrder);

            ExecuteRequest(request);
        }
    }
}
