﻿using RestSharp;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using timw255.Sitefinity.RestClient.Model;

namespace timw255.Sitefinity.RestClient.ServiceWrappers.Ecommerce.Catalog
{
    public class ProductAttributeValueServiceWrapper : ServiceWrapper
    {
        public ProductAttributeValueServiceWrapper(SitefinityRestClient sf)
        {
            this.ServiceUrl = "Sitefinity/Services/Ecommerce/Catalog/ProductAttributeValue.svc/";
            this.SF = sf;
        }

        //[WebInvoke(Method = "POST", UriTemplate = "/batch/?provider={provider}&language={deletedLanguage}")]
        public bool BatchDeleteProductAttributeValues(Guid[] valueIds, string provider, string deletedLanguage)
        {
            var request = new RestRequest(this.GetServiceUrl("/batch/?provider={provider}&language={deletedLanguage}"), Method.POST);

            request.AddUrlSegment("provider", provider);
            request.AddUrlSegment("deletedLanguage", deletedLanguage);

            request.AddParameter("application/json", SerializeObject(valueIds), ParameterType.RequestBody);

            return ExecuteRequest<bool>(request);
        }

        //[WebInvoke(Method = "POST", UriTemplate = "/parent/{parentId}/batch/?provider={provider}&language={deletedLanguage}")]
        public bool BatchDeleteProductAttributeValuesWithParent(Guid parentId, Guid[] valueIds, string provider, string deletedLanguage)
        {
            var request = new RestRequest(this.GetServiceUrl("/parent/{parentId}/batch/?provider={provider}&language={deletedLanguage}"), Method.POST);

            request.AddUrlSegment("parentId", parentId.ToString());
            request.AddUrlSegment("provider", provider);
            request.AddUrlSegment("deletedLanguage", deletedLanguage);

            request.AddParameter("application/json", SerializeObject(valueIds), ParameterType.RequestBody);

            return ExecuteRequest<bool>(request);
        }

        //[WebInvoke(Method = "PUT", UriTemplate = "/parent/{parentId}/batch/place/?providerName={providerName}&placePosition={placePosition}&destination={destination}")]
        public CollectionContext<ProductAttributeValue> BatchPlaceAttributeValues(Guid[] sourceAttributeValueIds, Guid parentId, string providerName, string placePosition, string destination)
        {
            var request = new RestRequest(this.GetServiceUrl("/parent/{parentId}/batch/place/?providerName={providerName}&placePosition={placePosition}&destination={destination}"), Method.PUT);

            request.AddUrlSegment("parentId", parentId.ToString());
            request.AddUrlSegment("providerName", providerName);
            request.AddUrlSegment("placePosition", placePosition);
            request.AddUrlSegment("destination", destination);

            request.AddParameter("application/json", SerializeObject(sourceAttributeValueIds), ParameterType.RequestBody);

            return ExecuteRequest<CollectionContext<ProductAttributeValue>>(request);
        }

        //[WebInvoke(Method = "DELETE", UriTemplate = "/{valueId}/?provider={provider}&language={deletedLanguage}")]
        public bool DeleteProductAttributeValue(Guid valueId, string provider, string deletedLanguage)
        {
            var request = new RestRequest(this.GetServiceUrl("/{valueId}/?provider={provider}&language={deletedLanguage}"), Method.DELETE);

            request.AddUrlSegment("valueId", valueId.ToString());
            request.AddUrlSegment("provider", provider);
            request.AddUrlSegment("deletedLanguage", deletedLanguage);

            return ExecuteRequest<bool>(request);
        }

        //[WebInvoke(Method = "DELETE", UriTemplate = "/parent/{parentId}/{valueId}/?provider={provider}&language={deletedLanguage}")]
        public bool DeleteProductAttributeValueWithParent(Guid parentId, Guid valueId, string provider, string deletedLanguage)
        {
            var request = new RestRequest(this.GetServiceUrl("/parent/{parentId}/{valueId}/?provider={provider}&language={deletedLanguage}"), Method.DELETE);

            request.AddUrlSegment("parentId", parentId.ToString());
            request.AddUrlSegment("valueId", valueId.ToString());
            request.AddUrlSegment("provider", provider);
            request.AddUrlSegment("deletedLanguage", deletedLanguage);

            return ExecuteRequest<bool>(request);
        }

        //[WebGet(UriTemplate = "/active/parent/{parentId}/?provider={provider}&sortExpression={sortExpression}&skip={skip}&take={take}&filter={filter}")]
        public CollectionContext<ProductAttributeValue> GetActiveChildrenProductAttributeValues(Guid parentId, string provider, string sortExpression, int skip, int take, string filter)
        {
            var request = new RestRequest(this.GetServiceUrl("/active/parent/{parentId}/?provider={provider}&sortExpression={sortExpression}&skip={skip}&take={take}&filter={filter}"), Method.GET);

            request.AddUrlSegment("parentId", parentId.ToString());
            request.AddUrlSegment("provider", provider);
            request.AddUrlSegment("sortExpression", sortExpression);
            request.AddUrlSegment("skip", skip.ToString());
            request.AddUrlSegment("take", take.ToString());
            request.AddUrlSegment("filter", filter);

            return ExecuteRequest<CollectionContext<ProductAttributeValue>>(request);
        }

        //[WebGet(UriTemplate = "/parent/{parentId}/{valueId}/?provider={provider}")]
        public ItemContext<ProductAttributeValue> GetChildProductAttributeValue(Guid parentId, Guid valueId, string provider)
        {
            var request = new RestRequest(this.GetServiceUrl("/parent/{parentId}/{valueId}/?provider={provider}"), Method.GET);

            request.AddUrlSegment("parentId", parentId.ToString());
            request.AddUrlSegment("valueId", valueId.ToString());
            request.AddUrlSegment("provider", provider);

            return ExecuteRequest<ItemContext<ProductAttributeValue>>(request);
        }

        //[WebGet(UriTemplate = "/parent/{parentId}/?provider={provider}&sortExpression={sortExpression}&skip={skip}&take={take}&filter={filter}")]
        public CollectionContext<ProductAttributeValue> GetChildrenProductAttributeValues(Guid parentId, string provider, string sortExpression, int skip, int take, string filter)
        {
            var request = new RestRequest(this.GetServiceUrl("/parent/{parentId}/?provider={provider}&sortExpression={sortExpression}&skip={skip}&take={take}&filter={filter}"), Method.GET);

            request.AddUrlSegment("parentId", parentId.ToString());
            request.AddUrlSegment("provider", provider);
            request.AddUrlSegment("sortExpression", sortExpression);
            request.AddUrlSegment("skip", skip.ToString());
            request.AddUrlSegment("take", take.ToString());
            request.AddUrlSegment("filter", filter);

            return ExecuteRequest<CollectionContext<ProductAttributeValue>>(request);
        }

        //[WebGet(UriTemplate = "/predecessor/{valueId}/?provider={provider}&sortExpression={sortExpression}&skip={skip}&take={take}&filter={filter}")]
        public CollectionContext<ProductAttributeValue> GetPredecessorItems(Guid valueId, string provider, string sortExpression, int skip, int take, string filter)
        {
            var request = new RestRequest(this.GetServiceUrl("/predecessor/{valueId}/?provider={provider}&sortExpression={sortExpression}&skip={skip}&take={take}&filter={filter}"), Method.GET);

            request.AddUrlSegment("valueId", valueId.ToString());
            request.AddUrlSegment("provider", provider);
            request.AddUrlSegment("sortExpression", sortExpression);
            request.AddUrlSegment("skip", skip.ToString());
            request.AddUrlSegment("take", take.ToString());
            request.AddUrlSegment("filter", filter);

            return ExecuteRequest<CollectionContext<ProductAttributeValue>>(request);
        }

        //[WebGet(UriTemplate = "/{valueId}/?provider={provider}")]
        public ItemContext<ProductAttributeValue> GetProductAttributeValue(Guid valueId, string provider)
        {
            var request = new RestRequest(this.GetServiceUrl("/{valueId}/?provider={provider}"), Method.GET);

            request.AddUrlSegment("valueId", valueId.ToString());
            request.AddUrlSegment("provider", provider);

            return ExecuteRequest<ItemContext<ProductAttributeValue>>(request);
        }

        //[WebGet(UriTemplate = "/?provider={provider}&sortExpression={sortExpression}&skip={skip}&take={take}&filter={filter}")]
        public CollectionContext<ProductAttributeValue> GetProductAttributeValues(string provider, string sortExpression, int skip, int take, string filter)
        {
            var request = new RestRequest(this.GetServiceUrl("/?provider={provider}&sortExpression={sortExpression}&skip={skip}&take={take}&filter={filter}"), Method.GET);

            request.AddUrlSegment("provider", provider);
            request.AddUrlSegment("sortExpression", sortExpression);
            request.AddUrlSegment("skip", skip.ToString());
            request.AddUrlSegment("take", take.ToString());
            request.AddUrlSegment("filter", filter);

            return ExecuteRequest<CollectionContext<ProductAttributeValue>>(request);
        }

        //[WebInvoke(Method = "POST", UriTemplate = "/makeactive/?provider={provider}")]
        public bool MakeActive(Guid attributeValueId, string provider)
        {
            var request = new RestRequest(this.GetServiceUrl("/makeactive/?provider={provider}"), Method.POST);

            request.AddUrlSegment("provider", provider);

            request.AddParameter("application/json", SerializeObject(attributeValueId), ParameterType.RequestBody);

            return ExecuteRequest<bool>(request);
        }

        //[WebInvoke(Method = "POST", UriTemplate = "/makeinactive/?provider={provider}")]
        public bool MakeInActive(Guid attributeValueId, string provider)
        {
            var request = new RestRequest(this.GetServiceUrl("/makeinactive/?provider={provider}"), Method.POST);

            request.AddUrlSegment("provider", provider);

            request.AddParameter("application/json", SerializeObject(attributeValueId), ParameterType.RequestBody);

            return ExecuteRequest<bool>(request);
        }

        //[WebInvoke(Method = "PUT", UriTemplate = "/{valueId}/?provider={provider}")]
        public ItemContext<ProductAttributeValue> SaveProductAttributeValue(Guid valueId, ItemContext<ProductAttributeValue> value, string provider)
        {
            var request = new RestRequest(this.GetServiceUrl("/{valueId}/?provider={provider}"), Method.PUT);

            request.AddUrlSegment("valueId", valueId.ToString());
            request.AddUrlSegment("provider", provider);

            request.AddParameter("application/json", SerializeObject(value), ParameterType.RequestBody);

            return ExecuteRequest<ItemContext<ProductAttributeValue>>(request);
        }

        //[WebInvoke(Method = "PUT", UriTemplate = "/parent/{parentId}/{valueId}/?provider={provider}")]
        public ItemContext<ProductAttributeValue> SaveProductAttributeValueWithParent(Guid parentId, Guid valueId, ItemContext<ProductAttributeValue> value, string provider)
        {
            var request = new RestRequest(this.GetServiceUrl("/parent/{parentId}/{valueId}/?provider={provider}"), Method.PUT);

            request.AddUrlSegment("parentId", parentId.ToString());
            request.AddUrlSegment("valueId", valueId.ToString());
            request.AddUrlSegment("provider", provider);

            request.AddParameter("application/json", SerializeObject(value), ParameterType.RequestBody);

            return ExecuteRequest<ItemContext<ProductAttributeValue>>(request);
        }
    }
}
