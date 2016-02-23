﻿using RestSharp;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using timw255.Sitefinity.RestClient.Model;

namespace timw255.Sitefinity.RestClient.ServiceWrappers.Ecommerce.Catalog
{
    public class ProductServiceWrapper : ServiceWrapper
    {
        public ProductServiceWrapper(SitefinityRestClient sf)
        {
            this.ServiceUrl = "Sitefinity/Services/Ecommerce/Catalog/ProductService.svc/";
            this.SF = sf;
        }

        //[WebInvoke(Method = "POST", UriTemplate = "/batch/?provider={provider}&language={deletedLanguage}")]
        public bool BatchDeleteProducts(Guid[] productIds, string provider, string deletedLanguage)
        {
            var request = new RestRequest(this.GetServiceUrl("/batch/?provider={provider}&language={deletedLanguage}"), Method.POST);

            request.AddUrlSegment("provider", provider);
            request.AddUrlSegment("deletedLanguage", deletedLanguage);

            request.AddParameter("application/json", SerializeObject(productIds), ParameterType.RequestBody);

            return ExecuteRequest<bool>(request);
        }

        //[WebInvoke(Method = "PUT", UriTemplate = "batch/publish/?provider={providerName}&workflowOperation={workflowOperation}")]
        public bool BatchPublishProducts(Guid[] ids, string providerName, string workflowOperation)
        {
            var request = new RestRequest(this.GetServiceUrl("batch/publish/?provider={providerName}&workflowOperation={workflowOperation}"), Method.PUT);

            request.AddUrlSegment("providerName", providerName);
            request.AddUrlSegment("workflowOperation", workflowOperation);

            request.AddParameter("application/json", SerializeObject(ids), ParameterType.RequestBody);

            return ExecuteRequest<bool>(request);
        }

        //[WebInvoke(Method = "PUT", UriTemplate = "batch/unpublish/?provider={providerName}&workflowOperation={workflowOperation}")]
        public bool BatchUnpublishProducts(Guid[] ids, string providerName, string workflowOperation)
        {
            var request = new RestRequest(this.GetServiceUrl("batch/unpublish/?provider={providerName}&workflowOperation={workflowOperation}"), Method.PUT);

            request.AddUrlSegment("providerName", providerName);
            request.AddUrlSegment("workflowOperation", workflowOperation);

            request.AddParameter("application/json", SerializeObject(ids), ParameterType.RequestBody);

            return ExecuteRequest<bool>(request);
        }

        //[WebInvoke(Method = "DELETE", UriTemplate = "/{productId}/?provider={provider}&language={deletedLanguage}")]
        public bool DeleteProduct(Guid productId, string provider, string deletedLanguage)
        {
            var request = new RestRequest(this.GetServiceUrl("/{productId}/?provider={provider}&language={deletedLanguage}"), Method.DELETE);

            request.AddUrlSegment("productId", productId.ToString());
            request.AddUrlSegment("provider", provider);
            request.AddUrlSegment("deletedLanguage", deletedLanguage);

            return ExecuteRequest<bool>(request);
        }

        //[WebInvoke(Method = "DELETE", UriTemplate = "/temp/{productId}/?provider={providerName}&force={force}&workflowOperation={workflowOperation}")]
        public bool DeleteTemp(Guid productId, string providerName, bool force, string workflowOperation)
        {
            var request = new RestRequest(this.GetServiceUrl("/temp/{productId}/?provider={providerName}&force={force}&workflowOperation={workflowOperation}"), Method.DELETE);

            request.AddUrlSegment("productId", productId.ToString());
            request.AddUrlSegment("providerName", providerName);
            request.AddUrlSegment("force", force.ToString());
            request.AddUrlSegment("workflowOperation", workflowOperation);

            return ExecuteRequest<bool>(request);
        }

        //[WebGet(UriTemplate = "/{productId}/?providerName={providerName}&checkOut={checkOut}")]
        public ContentItemContext<Product> GetProduct(Guid productId, string providerName, bool checkOut)
        {
            var request = new RestRequest(this.GetServiceUrl("/{productId}/?providerName={providerName}&checkOut={checkOut}"), Method.GET);

            request.AddUrlSegment("productId", productId.ToString());
            request.AddUrlSegment("providerName", providerName);
            request.AddUrlSegment("checkOut", checkOut.ToString());

            return ExecuteRequest<ContentItemContext<Product>>(request);
        }

        //[WebGet(UriTemplate = "/?provider={provider}&sortExpression={sortExpression}&skip={skip}&take={take}&filter={filter}&specificProductType={specificProductType}&otherFilters={otherFilters}")]
        public CollectionContext<ProductViewModel> GetProducts(string provider, string sortExpression, int skip, int take, string filter, string specificProductType, string otherFilters)
        {
            var request = new RestRequest(this.GetServiceUrl("/?provider={provider}&sortExpression={sortExpression}&skip={skip}&take={take}&filter={filter}&specificProductType={specificProductType}&otherFilters={otherFilters}"), Method.GET);

            request.AddUrlSegment("provider", provider);
            request.AddUrlSegment("sortExpression", sortExpression);
            request.AddUrlSegment("skip", skip.ToString());
            request.AddUrlSegment("take", take.ToString());
            request.AddUrlSegment("filter", filter);
            request.AddUrlSegment("specificProductType", specificProductType);
            request.AddUrlSegment("otherFilters", otherFilters);

            return ExecuteRequest<CollectionContext<ProductViewModel>>(request);
        }

        //[WebInvoke(Method = "PUT", UriTemplate = "/{productId}/?provider={provider}&itemType={itemType}&workflowOperation={workflowOperation}")]
        public ContentItemContext<Product> SaveProduct(Guid productId, string serializedProduct, string provider, string itemType, string workflowOperation)
        {
            var request = new RestRequest(this.GetServiceUrl("/{productId}/?provider={provider}&itemType={itemType}&workflowOperation={workflowOperation}"), Method.PUT);

            request.AddUrlSegment("productId", productId.ToString());
            request.AddUrlSegment("provider", provider);
            request.AddUrlSegment("itemType", itemType);
            request.AddUrlSegment("workflowOperation", workflowOperation);

            request.AddParameter("application/json", SerializeObject(serializedProduct), ParameterType.RequestBody);

            return ExecuteRequest<ContentItemContext<Product>>(request);
        }
    }
}
