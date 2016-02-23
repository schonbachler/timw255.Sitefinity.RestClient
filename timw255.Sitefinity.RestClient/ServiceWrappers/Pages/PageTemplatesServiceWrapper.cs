﻿using RestSharp;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading.Tasks;
using timw255.Sitefinity.RestClient.Model;

namespace timw255.Sitefinity.RestClient.ServiceWrappers.Pages
{
    public class PageTemplatesServiceWrapper : ServiceWrapper
    {
        public PageTemplatesServiceWrapper(SitefinityRestClient sf)
        {
            this.ServiceUrl = "Sitefinity/Services/Pages/PageTemplatesService.svc/";
            this.SF = sf;
        }

        //[WebInvoke(Method = "POST", UriTemplate = "batch/?providerName={providerName}&language={deletedLanguage}")]
        public bool BatchDeletePageTemplates(Guid[] Ids, string providerName, string deletedLanguage)
        {
            var request = new RestRequest(this.GetServiceUrl("batch/?providerName={providerName}&language={deletedLanguage}"), Method.POST);

            request.AddUrlSegment("providerName", providerName);
            request.AddUrlSegment("deletedLanguage", deletedLanguage);

            request.AddParameter("application/json", SerializeObject(Ids), ParameterType.RequestBody);

            return ExecuteRequest<bool>(request);
        }

        //[WebInvoke(Method = "PUT", UriTemplate = "batchPublishDraft/")]
        public void BatchPublishDraft(Guid[] templateIDs)
        {
            var request = new RestRequest(this.GetServiceUrl("batchPublishDraft/"), Method.PUT);

            request.AddParameter("application/json", SerializeObject(templateIDs), ParameterType.RequestBody);

            ExecuteRequest(request);
        }

        //[WebInvoke(Method = "PUT", UriTemplate = "changeTemplate/{templateId}/?newTemplateId={newTemplateId}")]
        public bool ChangeTemplate(Guid templateId, Guid newTemplateId)
        {
            var request = new RestRequest(this.GetServiceUrl("changeTemplate/{templateId}/?newTemplateId={newTemplateId}"), Method.PUT);

            request.AddUrlSegment("templateId", templateId.ToString());
            request.AddUrlSegment("newTemplateId", newTemplateId.ToString());

            return ExecuteRequest<bool>(request);
        }

        //[WebInvoke(Method = "DELETE", UriTemplate = "{templateId}/?providerName={providerName}&language={deletedLanguage}")]
        public bool DeletePageTemplate(Guid templateId, string providerName, string deletedLanguage)
        {
            var request = new RestRequest(this.GetServiceUrl("{templateId}/?providerName={providerName}&language={deletedLanguage}"), Method.DELETE);

            request.AddUrlSegment("templateId", templateId.ToString());
            request.AddUrlSegment("providerName", providerName);
            request.AddUrlSegment("deletedLanguage", deletedLanguage);

            return ExecuteRequest<bool>(request);
        }

        //[WebGet(UriTemplate = "?pageFilter={pageFilter}&sortExpression={sortExpression}&skip={skip}&take={take}&filter={filter}&root={root}")]
        public CollectionContext<PageTemplateViewModel> GetPageTemlatesInCondition(string pageFilter, string sortExpression, int skip, int take, string filter, string root)
        {
            var request = new RestRequest(this.GetServiceUrl("?pageFilter={pageFilter}&sortExpression={sortExpression}&skip={skip}&take={take}&filter={filter}&root={root}"), Method.GET);

            request.AddUrlSegment("pageFilter", pageFilter);
            request.AddUrlSegment("sortExpression", sortExpression);
            request.AddUrlSegment("skip", skip.ToString());
            request.AddUrlSegment("take", take.ToString());
            request.AddUrlSegment("filter", filter);
            request.AddUrlSegment("root", root);

            return ExecuteRequest<CollectionContext<PageTemplateViewModel>>(request);
        }

        //[WebGet(UriTemplate = "{templateId}/?providerName={providerName}")]
        public WcfPageTemplateContext GetPageTemplate(Guid templateId, string providerName)
        {
            var request = new RestRequest(this.GetServiceUrl("{templateId}/?providerName={providerName}"), Method.GET);

            request.AddUrlSegment("templateId", templateId.ToString());
            request.AddUrlSegment("providerName", providerName);

            return ExecuteRequest<WcfPageTemplateContext>(request);
        }

        //[WebGet(UriTemplate = "/sitelinks/{templateId}/?sortExpression={sortExpression}&skip={skip}&take={take}&filter={filter}")]
        public CollectionContext<SiteItemLinkViewModel> GetSharedSites(Guid templateId, string sortExpression, int skip, int take, string filter)
        {
            var request = new RestRequest(this.GetServiceUrl("/sitelinks/{templateId}/?sortExpression={sortExpression}&skip={skip}&take={take}&filter={filter}"), Method.GET);

            request.AddUrlSegment("templateId", templateId.ToString());
            request.AddUrlSegment("sortExpression", sortExpression);
            request.AddUrlSegment("skip", skip.ToString());
            request.AddUrlSegment("take", take.ToString());
            request.AddUrlSegment("filter", filter);

            return ExecuteRequest<CollectionContext<SiteItemLinkViewModel>>(request);
        }

        //[WebInvoke(Method = "PUT", UriTemplate = "{templateId}/?itemType={itemType}&providerName={providerName}&managerType={managerType}&duplicate={duplicate}")]
        public WcfPageTemplateContext SavePageTemplate(WcfPageTemplateContext templateContext, Guid templateId, string itemType, string providerName, string managerType, bool duplicate)
        {
            var request = new RestRequest(this.GetServiceUrl("{templateId}/?itemType={itemType}&providerName={providerName}&managerType={managerType}&duplicate={duplicate}"), Method.PUT);

            request.AddUrlSegment("templateId", templateId.ToString());
            request.AddUrlSegment("itemType", itemType);
            request.AddUrlSegment("providerName", providerName);
            request.AddUrlSegment("managerType", managerType);
            request.AddUrlSegment("duplicate", duplicate.ToString());

            request.AddParameter("application/json", SerializeObject(templateContext), ParameterType.RequestBody);

            return ExecuteRequest<WcfPageTemplateContext>(request);
        }

        //[WebInvoke(Method = "PUT", UriTemplate = "/savesitelinks/{templateId}/")]
        public bool SaveSharedSites(Guid templateId, Guid[] sharedSiteIDs)
        {
            var request = new RestRequest(this.GetServiceUrl("/savesitelinks/{templateId}/"), Method.PUT);

            request.AddUrlSegment("templateId", templateId.ToString());

            request.AddParameter("application/json", SerializeObject(sharedSiteIDs), ParameterType.RequestBody);

            return ExecuteRequest<bool>(request);
        }
    }
}
