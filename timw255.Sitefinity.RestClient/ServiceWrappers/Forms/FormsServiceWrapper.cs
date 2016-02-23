﻿using RestSharp;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading.Tasks;
using timw255.Sitefinity.RestClient.Model;

namespace timw255.Sitefinity.RestClient.ServiceWrappers.Forms
{
    public class FormsServiceWrapper : ServiceWrapper
    {
        public FormsServiceWrapper(SitefinityRestClient sf)
        {
            this.ServiceUrl = "Sitefinity/Services/Forms/FormsService.svc/";
            this.SF = sf;
        }

        //[WebInvoke(Method = "PUT", UriTemplate = "AddLanguage/{languageCode}/?providerName={providerName}")]
        public void AddFormLanguageVersion(Guid formId, string languageCode, string providerName)
        {
            var request = new RestRequest(this.GetServiceUrl("AddLanguage/{languageCode}/?providerName={providerName}"), Method.PUT);

            request.AddUrlSegment("languageCode", languageCode);
            request.AddUrlSegment("providerName", providerName);

            request.AddParameter("application/json", SerializeObject(formId), ParameterType.RequestBody);

            ExecuteRequest(request);
        }

        //[WebInvoke(Method = "POST", UriTemplate = "batch/?providerName={providerName}&language={languageToDelete}")]
        public bool BatchDeleteFormDescription(Guid[] ids, string providerName, string languageToDelete)
        {
            var request = new RestRequest(this.GetServiceUrl("batch/?providerName={providerName}&language={languageToDelete}"), Method.POST);

            request.AddUrlSegment("providerName", providerName);
            request.AddUrlSegment("languageToDelete", languageToDelete);

            request.AddParameter("application/json", SerializeObject(ids), ParameterType.RequestBody);

            return ExecuteRequest<bool>(request);
        }

        //[WebInvoke(Method = "POST", UriTemplate = "entries/{formName}/batch/?providerName={providerName}")]
        public bool BatchDeleteFormEntries(Guid[] ids, string formName, string providerName)
        {
            var request = new RestRequest(this.GetServiceUrl("entries/{formName}/batch/?providerName={providerName}"), Method.POST);

            request.AddUrlSegment("formName", formName);
            request.AddUrlSegment("providerName", providerName);

            request.AddParameter("application/json", SerializeObject(ids), ParameterType.RequestBody);

            return ExecuteRequest<bool>(request);
        }

        //[WebInvoke(Method = "PUT", UriTemplate = "batch/publish/?providerName={providerName}")]
        public bool BatchPublishForm(Guid[] formIds, string providerName)
        {
            var request = new RestRequest(this.GetServiceUrl("batch/publish/?providerName={providerName}"), Method.PUT);

            request.AddUrlSegment("providerName", providerName);

            request.AddParameter("application/json", SerializeObject(formIds), ParameterType.RequestBody);

            return ExecuteRequest<bool>(request);
        }

        //[WebInvoke(Method = "PUT", UriTemplate = "batch/?providerName={providerName}")]
        public void BatchSaveFormDescription(FormDescriptionViewModel[] formContext, string providerName)
        {
            var request = new RestRequest(this.GetServiceUrl("batch/?providerName={providerName}"), Method.PUT);

            request.AddUrlSegment("providerName", providerName);

            request.AddParameter("application/json", SerializeObject(formContext), ParameterType.RequestBody);

            ExecuteRequest(request);
        }

        //[WebInvoke(Method = "PUT", UriTemplate = "batch/unpublish/?providerName={providerName}")]
        public void BatchUnpublishForm(Guid[] formIds, string providerName)
        {
            var request = new RestRequest(this.GetServiceUrl("batch/unpublish/?providerName={providerName}"), Method.PUT);

            request.AddUrlSegment("providerName", providerName);

            request.AddParameter("application/json", SerializeObject(formIds), ParameterType.RequestBody);

            ExecuteRequest(request);
        }

        //[WebInvoke(Method = "DELETE", UriTemplate = "{formId}/?providerName={providerName}&language={languageToDelete}")]
        public bool DeleteFormDescription(Guid formId, string providerName, string languageToDelete)
        {
            var request = new RestRequest(this.GetServiceUrl("{formId}/?providerName={providerName}&language={languageToDelete}"), Method.DELETE);

            request.AddUrlSegment("formId", formId.ToString());
            request.AddUrlSegment("providerName", providerName);
            request.AddUrlSegment("languageToDelete", languageToDelete);

            return ExecuteRequest<bool>(request);
        }

        //[WebInvoke(Method = "DELETE", UriTemplate = "/entry/{formName}/{entryId}/?providerName={providerName}&itemType={itemType}&managerType={managerType}")]
        public bool DeleteFormEntry(string formName, Guid entryId, string providerName, string itemType, string managerType)
        {
            var request = new RestRequest(this.GetServiceUrl("/entry/{formName}/{entryId}/?providerName={providerName}&itemType={itemType}&managerType={managerType}"), Method.DELETE);

            request.AddUrlSegment("formName", formName);
            request.AddUrlSegment("entryId", entryId.ToString());
            request.AddUrlSegment("providerName", providerName);
            request.AddUrlSegment("itemType", itemType);
            request.AddUrlSegment("managerType", managerType);

            return ExecuteRequest<bool>(request);
        }

        //[WebGet(UriTemplate = "{formId}/?providerName={providerName}&duplicate={duplicate}")]
        public FormDescriptionViewModelContext GetFormDescription(Guid formId, string providerName, bool duplicate)
        {
            var request = new RestRequest(this.GetServiceUrl("{formId}/?providerName={providerName}&duplicate={duplicate}"), Method.GET);

            request.AddUrlSegment("formId", formId.ToString());
            request.AddUrlSegment("providerName", providerName);
            request.AddUrlSegment("duplicate", duplicate.ToString());

            return ExecuteRequest<FormDescriptionViewModelContext>(request);
        }

        //[WebGet(UriTemplate = "?sortExpression={sortExpression}&skip={skip}&take={take}&filter={filter}&notShared={notShared}")]
        public CollectionContext<FormDescriptionViewModel> GetFormDescriptions(string filter, string sortExpression, int skip, int take, bool notShared)
        {
            var request = new RestRequest(this.GetServiceUrl("?sortExpression={sortExpression}&skip={skip}&take={take}&filter={filter}&notShared={notShared}"), Method.GET);

            request.AddUrlSegment("sortExpression", sortExpression);
            request.AddUrlSegment("skip", skip.ToString());
            request.AddUrlSegment("take", take.ToString());
            request.AddUrlSegment("filter", filter);
            request.AddUrlSegment("notShared", notShared.ToString());
            
            return ExecuteRequest<CollectionContext<FormDescriptionViewModel>>(request);
        }

        //[WebGet(UriTemplate = "entries/{formName}/?providerName={providerName}&sortExpression={sortExpression}&skip={skip}&take={take}&filter={filter}&itemType={itemType}&managerType={managerType}&siteId={siteId}")]
        public CollectionContext<FormEntry> GetFormEntries(string formName, string providerName, string sortExpression, int skip, int take, string filter, string itemType, string managerType, Guid siteId)
        {
            var request = new RestRequest(this.GetServiceUrl("entries/{formName}/?providerName={providerName}&sortExpression={sortExpression}&skip={skip}&take={take}&filter={filter}&itemType={itemType}&managerType={managerType}&siteId={siteId}"), Method.GET);

            request.AddUrlSegment("formName", formName);
            request.AddUrlSegment("providerName", providerName);
            request.AddUrlSegment("sortExpression", sortExpression);
            request.AddUrlSegment("skip", skip.ToString());
            request.AddUrlSegment("take", take.ToString());
            request.AddUrlSegment("filter", filter);
            request.AddUrlSegment("itemType", itemType);
            request.AddUrlSegment("managerType", managerType);
            request.AddUrlSegment("siteId", siteId.ToString());

            return ExecuteRequest<CollectionContext<FormEntry>>(request);
        }

        //[WebGet(UriTemplate = "/entry/{formName}/{entryId}/?providerName={providerName}&itemType={itemType}&managerType={managerType}")]
        public FormEntry GetFormEntry(string formName, Guid entryId, string providerName, string itemType, string managerType)
        {
            var request = new RestRequest(this.GetServiceUrl("/entry/{formName}/{entryId}/?providerName={providerName}&itemType={itemType}&managerType={managerType}"), Method.GET);

            request.AddUrlSegment("formName", formName);
            request.AddUrlSegment("entryId", entryId.ToString());
            request.AddUrlSegment("providerName", providerName);
            request.AddUrlSegment("itemType", itemType);
            request.AddUrlSegment("managerType", managerType);

            return ExecuteRequest<FormEntry>(request);
        }

        //[WebInvoke(Method = "PUT", UriTemplate = "/publish/?providerName={providerName}")]
        public void PublishForm(Guid formDraftId, string providerName)
        {
            var request = new RestRequest(this.GetServiceUrl("/publish/?providerName={providerName}"), Method.PUT);

            request.AddUrlSegment("providerName", providerName);

            request.AddParameter("application/json", SerializeObject(formDraftId), ParameterType.RequestBody);

            ExecuteRequest(request);
        }

        //[WebInvoke(Method = "PUT", UriTemplate = "{formId}/?providerName={providerName}&duplicate={duplicate}")]
        public FormDescriptionViewModelContext SaveFormDescription(FormDescriptionViewModelContext formContext, Guid formId, string providerName, bool duplicate)
        {
            var request = new RestRequest(this.GetServiceUrl("{formId}/?providerName={providerName}&duplicate={duplicate}"), Method.PUT);

            request.AddUrlSegment("formId", formId.ToString());
            request.AddUrlSegment("providerName", providerName);
            request.AddUrlSegment("duplicate", duplicate.ToString());

            request.AddParameter("application/json", SerializeObject(formContext), ParameterType.RequestBody);

            return ExecuteRequest<FormDescriptionViewModelContext>(request);
        }

        //[WebInvoke(Method = "PUT", UriTemplate = "/entry/{formName}/{entryId}/?providerName={providerName}&itemType={itemType}&managerType={managerType}")]
        public ContentItemContext<FormEntry> SaveFormEntry(ContentItemContext<FormEntry> entry, string formName, Guid entryId, string itemType, string providerName, string managerType)
        {
            var request = new RestRequest(this.GetServiceUrl("/entry/{formName}/{entryId}/?providerName={providerName}&itemType={itemType}&managerType={managerType}"), Method.PUT);

            request.AddUrlSegment("formName", formName);
            request.AddUrlSegment("entryId", entryId.ToString());
            request.AddUrlSegment("providerName", providerName);
            request.AddUrlSegment("itemType", itemType);
            request.AddUrlSegment("managerType", managerType);

            request.AddParameter("application/json", SerializeObject(entry), ParameterType.RequestBody);

            return ExecuteRequest<ContentItemContext<FormEntry>>(request);
        }

        //[WebInvoke(Method = "POST", UriTemplate = "share/?providerName={providerName}", BodyStyle = WebMessageBodyStyle.Wrapped)]
        public void ShareFormDescription(Guid formId, string providerName, string[] selectedSites)
        {
            var request = new RestRequest(this.GetServiceUrl("share/?providerName={providerName}"), Method.POST);

            request.AddUrlSegment("providerName", providerName);

            request.AddParameter("application/json", SerializeObject(formId), ParameterType.RequestBody);
            request.AddParameter("application/json", SerializeObject(selectedSites), ParameterType.RequestBody);

            ExecuteRequest(request);
        }

        //[WebInvoke(Method = "PUT", UriTemplate = "/subscribe/?providerName={providerName}")]
        public void SubscribeForm(Guid formId, string providerName)
        {
            var request = new RestRequest(this.GetServiceUrl("/subscribe/?providerName={providerName}"), Method.PUT);

            request.AddUrlSegment("providerName", providerName);

            request.AddParameter("application/json", SerializeObject(formId), ParameterType.RequestBody);

            ExecuteRequest(request);
        }

        //[WebInvoke(Method = "PUT", UriTemplate = "/unpublish/?providerName={providerName}")]
        public void UnpublishForm(Guid formId, string providerName)
        {
            var request = new RestRequest(this.GetServiceUrl("/unpublish/?providerName={providerName}"), Method.PUT);

            request.AddUrlSegment("providerName", providerName);

            request.AddParameter("application/json", SerializeObject(formId), ParameterType.RequestBody);

            ExecuteRequest(request);
        }

        //[WebInvoke(Method = "PUT", UriTemplate = "/unsubscribe/?providerName={providerName}")]
        public void UnsubscribeForm(Guid formId, string providerName)
        {
            var request = new RestRequest(this.GetServiceUrl("/unsubscribe/?providerName={providerName}"), Method.PUT);

            request.AddUrlSegment("providerName", providerName);

            request.AddParameter("application/json", SerializeObject(formId), ParameterType.RequestBody);

            ExecuteRequest(request);
        }
    }
}
