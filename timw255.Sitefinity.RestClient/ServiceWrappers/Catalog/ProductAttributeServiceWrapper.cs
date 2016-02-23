﻿using RestSharp;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading.Tasks;
using timw255.Sitefinity.RestClient.Model;
using timw255.Sitefinity.RestClient.SitefinityClient;

namespace timw255.Sitefinity.RestClient.ServiceWrappers.Catalog
{
    public class ProductAttributeServiceWrapper : ServiceWrapper
    {
        public ProductAttributeServiceWrapper(SitefinityRestClient sf)
        {
            this.ServiceUrl = "Sitefinity/Services/Catalog/ProductAttribute.svc/";
            this.SF = sf;
        }

        //[WebInvoke(Method = "POST", UriTemplate = "/batch/?provider={provider}&language={deletedLanguage}")]
        public bool BatchDeleteProductAttributes(Guid[] attributeIds, string provider, string deletedLanguage)
        {
            var request = new RestRequest(this.GetServiceUrl("/batch/?provider={provider}&language={deletedLanguage}"), Method.POST);

            request.AddUrlSegment("provider", provider);
            request.AddUrlSegment("deletedLanguage", deletedLanguage);

            request.AddParameter("application/json", SerializeObject(attributeIds), ParameterType.RequestBody);

            return ExecuteRequest<bool>(request);
        }

        //[WebInvoke(Method = "PUT", UriTemplate = "/batch/place/?providerName={providerName}&placePosition={placePosition}&destination={destination}")]
        public CollectionContext<ProductAttribute> BatchPlaceAttributes(Guid[] sourceAttributeValueIds, string providerName, string placePosition, string destination)
        {
            var request = new RestRequest(this.GetServiceUrl("/batch/place/?providerName={providerName}&placePosition={placePosition}&destination={destination}"), Method.PUT);

            request.AddUrlSegment("providerName", providerName);
            request.AddUrlSegment("placePosition", placePosition);
            request.AddUrlSegment("destination", destination);

            request.AddParameter("application/json", SerializeObject(sourceAttributeValueIds), ParameterType.RequestBody);

            return ExecuteRequest<CollectionContext<ProductAttribute>>(request);
        }

        //[WebInvoke(Method = "DELETE", UriTemplate = "/{attributeId}/?provider={provider}&language={deletedLanguage}")]
        public bool DeleteProductAttribute(Guid attributeId, string provider, string deletedLanguage)
        {
            var request = new RestRequest(this.GetServiceUrl("/{attributeId}/?provider={provider}&language={deletedLanguage}"), Method.DELETE);

            request.AddUrlSegment("attributeId", attributeId.ToString());
            request.AddUrlSegment("provider", provider);
            request.AddUrlSegment("deletedLanguage", deletedLanguage);

            return ExecuteRequest<bool>(request);
        }

        //[WebGet(UriTemplate = "/AllowedAttributes/{productId}/?provider={provider}&sortExpression={sortExpression}&skip={skip}&take={take}&filter={filter}")]
        public CollectionContext<ProductAttribute> GetAllowedProductAttributes(Guid productId, string provider, string sortExpression, int skip, int take, string filter)
        {
            var request = new RestRequest(this.GetServiceUrl("/AllowedAttributes/{productId}/?provider={provider}&sortExpression={sortExpression}&skip={skip}&take={take}&filter={filter}"), Method.GET);

            request.AddUrlSegment("productId", productId.ToString());
            request.AddUrlSegment("provider", provider);
            request.AddUrlSegment("sortExpression", sortExpression);
            request.AddUrlSegment("skip", skip.ToString());
            request.AddUrlSegment("take", take.ToString());
            request.AddUrlSegment("filter", filter);

            return ExecuteRequest<CollectionContext<ProductAttribute>>(request);
        }

        //[WebGet(UriTemplate = "/predecessor/{valueId}/?provider={provider}&sortExpression={sortExpression}&skip={skip}&take={take}&filter={filter}")]
        public CollectionContext<ProductAttribute> GetPredecessorItems(Guid valueId, string provider, string sortExpression, int skip, int take, string filter)
        {
            var request = new RestRequest(this.GetServiceUrl("/predecessor/{valueId}/?provider={provider}&sortExpression={sortExpression}&skip={skip}&take={take}&filter={filter}"), Method.GET);

            request.AddUrlSegment("valueId", valueId.ToString());
            request.AddUrlSegment("provider", provider);
            request.AddUrlSegment("sortExpression", sortExpression);
            request.AddUrlSegment("skip", skip.ToString());
            request.AddUrlSegment("take", take.ToString());
            request.AddUrlSegment("filter", filter);

            return ExecuteRequest<CollectionContext<ProductAttribute>>(request);
        }

        //[WebGet(UriTemplate = "/{attributeId}/?provider={provider}")]
        public ItemContext<ProductAttribute> GetProductAttribute(Guid attributeId, string provider)
        {
            var request = new RestRequest(this.GetServiceUrl("/{attributeId}/?provider={provider}"), Method.GET);

            request.AddUrlSegment("attributeId", attributeId.ToString());
            request.AddUrlSegment("provider", provider);
            
            return ExecuteRequest<ItemContext<ProductAttribute>>(request);
        }

        //[WebGet(UriTemplate = "/?provider={provider}&sortExpression={sortExpression}&skip={skip}&take={take}&filter={filter}")]
        public CollectionContext<ProductAttribute> GetProductAttributes(string provider, string sortExpression, int skip, int take, string filter)
        {
            var request = new RestRequest(this.GetServiceUrl("/?provider={provider}&sortExpression={sortExpression}&skip={skip}&take={take}&filter={filter}"), Method.GET);

            request.AddUrlSegment("provider", provider);
            request.AddUrlSegment("sortExpression", sortExpression);
            request.AddUrlSegment("skip", skip.ToString());
            request.AddUrlSegment("take", take.ToString());
            request.AddUrlSegment("filter", filter);

            return ExecuteRequest<CollectionContext<ProductAttribute>>(request);
        }

        //[WebInvoke(Method = "POST", UriTemplate = "/makeactive/?provider={provider}")]
        public bool MakeActive(Guid attributeId, string provider)
        {
            var request = new RestRequest(this.GetServiceUrl("/makeactive/?provider={provider}"), Method.POST);

            request.AddUrlSegment("provider", provider);

            request.AddParameter("application/json", SerializeObject(attributeId), ParameterType.RequestBody);

            return ExecuteRequest<bool>(request);
        }

        //[WebInvoke(Method = "POST", UriTemplate = "/makeinactive/?provider={provider}")]
        public bool MakeInActive(Guid attributeId, string provider)
        {
            var request = new RestRequest(this.GetServiceUrl("/makeinactive/?provider={provider}"), Method.POST);

            request.AddUrlSegment("provider", provider);

            request.AddParameter("application/json", SerializeObject(attributeId), ParameterType.RequestBody);

            return ExecuteRequest<bool>(request);
        }

        //[WebInvoke(Method = "PUT", UriTemplate = "/{attributeId}/?provider={provider}")]
        public ItemContext<ProductAttribute> SaveProductAttribute(Guid attributeId, ItemContext<ProductAttribute> attribute, string provider)
        {
            var request = new RestRequest(this.GetServiceUrl("/{attributeId}/?provider={provider}"), Method.PUT);

            request.AddUrlSegment("attributeId", attributeId.ToString());
            request.AddUrlSegment("provider", provider);

            request.AddParameter("application/json", SerializeObject(attribute), ParameterType.RequestBody);

            return ExecuteRequest<ItemContext<ProductAttribute>>(request);
        }
    }
}
