﻿using RestSharp;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading.Tasks;
using timw255.Sitefinity.RestClient.Model;

namespace timw255.Sitefinity.RestClient.ServiceWrappers.Security
{
    public class RolesServiceWrapper : ServiceWrapper
    {
        public RolesServiceWrapper(SitefinityRestClient sf)
        {
            this.ServiceUrl = "Sitefinity/Services/Security/Roles.svc/";
            this.SF = sf;
        }

        //[WebInvoke(Method = "DELETE", UriTemplate = "{roleId}/?provider={provider}")]
        public bool DeleteRole(Guid roleId, string provider)
        {
            var request = new RestRequest(this.GetServiceUrl("{roleId}/?provider={provider}"), Method.DELETE);

            request.AddUrlSegment("roleId", roleId.ToString());
            request.AddUrlSegment("provider", provider);

            return ExecuteRequest<bool>(request);
        }

        //[WebInvoke(Method = "DELETE", UriTemplate = "{roleId}/{userId}/?provider={provider}")]
        public bool DeleteRoleUser(Guid roleId, Guid userId, string provider)
        {
            var request = new RestRequest(this.GetServiceUrl("{roleId}/{userId}/?provider={provider}"), Method.DELETE);

            request.AddUrlSegment("roleId", roleId.ToString());
            request.AddUrlSegment("userId", userId.ToString());
            request.AddUrlSegment("provider", provider);

            return ExecuteRequest<bool>(request);
        }

        //[WebGet(UriTemplate = "CountRoleUsers/{roleId}/{provider}")]
        public int GetCountOfUsersInRole(Guid roleId, string provider)
        {
            var request = new RestRequest(this.GetServiceUrl("CountRoleUsers/{roleId}/{provider}"), Method.GET);

            request.AddUrlSegment("roleId", roleId.ToString());
            request.AddUrlSegment("provider", provider);

            return ExecuteRequest<int>(request);
        }

        //[WebInvoke(Method = "PUT", RequestFormat = WebMessageFormat.Json, UriTemplate = "countWithLocalChanges/?roleProvider={roleProvider}&roleId={roleId}&filter={filter}&userProvider={userProvider}&forAllProviders={forAllUserProviders}")]
        public int GetNumOfUsersInRoleWithLocalChanges(UserProviderPair[] localChange, Guid roleId, string roleProvider, string filter, string userProvider, bool forAllUserProviders)
        {
            var request = new RestRequest(this.GetServiceUrl("countWithLocalChanges/?roleProvider={roleProvider}&roleId={roleId}&filter={filter}&userProvider={userProvider}&forAllProviders={forAllUserProviders}"), Method.PUT);

            request.AddUrlSegment("roleProvider", roleProvider);
            request.AddUrlSegment("roleId", roleId.ToString());
            request.AddUrlSegment("filter", filter);
            request.AddUrlSegment("userProvider", userProvider);
            request.AddUrlSegment("forAllUserProviders", forAllUserProviders.ToString());

            request.AddParameter("application/json", SerializeObject(localChange), ParameterType.RequestBody);

            return ExecuteRequest<int>(request);
        }

        //[WebGet(UriTemplate = "{roleId}/?provider={provider}")]
        public WcfRole GetRole(Guid roleId, string provider)
        {
            var request = new RestRequest(this.GetServiceUrl("{roleId}/?provider={provider}"), Method.GET);

            request.AddUrlSegment("roleId", roleId.ToString());
            request.AddUrlSegment("provider", provider);

            return ExecuteRequest<WcfRole>(request);
        }

        //[WebGet(UriTemplate = "/GetRoleProviders/?abilities={commaSeperatedAbilities}")]
        public CollectionContext<RoleProviderItem> GetRoleProviders(string commaSeperatedAbilities)
        {
            var request = new RestRequest(this.GetServiceUrl("/GetRoleProviders/?abilities={commaSeperatedAbilities}"), Method.GET);

            request.AddUrlSegment("commaSeperatedAbilities", commaSeperatedAbilities);

            return ExecuteRequest<CollectionContext<RoleProviderItem>>(request);
        }

        //[WebGet(UriTemplate = "/?provider={provider}&sortExpression={sortExpression}&skip={skip}&take={take}&filter={filter}")]
        public CollectionContext<WcfRole> GetRoles(string provider, string sortExpression, int skip, int take, string filter)
        {
            var request = new RestRequest(this.GetServiceUrl("/?provider={provider}&sortExpression={sortExpression}&skip={skip}&take={take}&filter={filter}"), Method.GET);

            request.AddUrlSegment("provider", provider);
            request.AddUrlSegment("sortExpression", sortExpression);
            request.AddUrlSegment("skip", skip.ToString());
            request.AddUrlSegment("take", take.ToString());
            request.AddUrlSegment("filter", filter);

            return ExecuteRequest<CollectionContext<WcfRole>>(request);
        }

        //[WebGet(UriTemplate = "membershipProviderCount/?provider={provider}&sortExpression={sortExpression}&skip={skip}&take={take}&filter={filter}&membershipProvider={membershipProvider}")]
        public CollectionContext<WcfRole> GetRolesWithUserCountPerMembershipProvider(string provider, string sortExpression, int skip, int take, string filter, string membershipProvider)
        {
            var request = new RestRequest(this.GetServiceUrl("membershipProviderCount/?provider={provider}&sortExpression={sortExpression}&skip={skip}&take={take}&filter={filter}&membershipProvider={membershipProvider}"), Method.GET);

            request.AddUrlSegment("provider", provider);
            request.AddUrlSegment("sortExpression", sortExpression);
            request.AddUrlSegment("skip", skip.ToString());
            request.AddUrlSegment("take", take.ToString());
            request.AddUrlSegment("filter", filter);
            request.AddUrlSegment("membershipProvider", membershipProvider);

            return ExecuteRequest<CollectionContext<WcfRole>>(request);
        }

        //[WebGet(UriTemplate = "GetRoleUsers/{roleId}/?provider={provider}&sortExpression={sortExpression}&skip={skip}&take={take}&filter={filter}")]
        public CollectionContext<UserProviderPair> GetRoleUsers(Guid roleId, string provider, string sortExpression, int skip, int take, string filter)
        {
            var request = new RestRequest(this.GetServiceUrl("GetRoleUsers/{roleId}/?provider={provider}&sortExpression={sortExpression}&skip={skip}&take={take}&filter={filter}"), Method.GET);

            request.AddUrlSegment("roleId", roleId.ToString());
            request.AddUrlSegment("provider", provider);
            request.AddUrlSegment("sortExpression", sortExpression);
            request.AddUrlSegment("skip", skip.ToString());
            request.AddUrlSegment("take", take.ToString());
            request.AddUrlSegment("filter", filter);

            return ExecuteRequest<CollectionContext<UserProviderPair>>(request);
        }

        //[WebInvoke(Method = "PUT", UriTemplate = "GetWcfUsersInRole/{roleId}/?provider={provider}&sortExpression={sortExpression}&skip={skip}&take={take}&filter={filter}&userProvider={userProvider}&forAllUserProviders={forAllUserProviders}", RequestFormat = WebMessageFormat.Json)]
        public CollectionContext<WcfMembershipUser> GetWcfUsersInRole(UserProviderPair[] localChange, Guid roleId, string provider, string sortExpression, int skip, int take, string filter, string userProvider, bool forAllUserProviders)
        {
            var request = new RestRequest(this.GetServiceUrl("GetWcfUsersInRole/{roleId}/?provider={provider}&sortExpression={sortExpression}&skip={skip}&take={take}&filter={filter}&userProvider={userProvider}&forAllUserProviders={forAllUserProviders}"), Method.PUT);

            request.AddUrlSegment("roleId", roleId.ToString());
            request.AddUrlSegment("provider", provider);
            request.AddUrlSegment("sortExpression", sortExpression);
            request.AddUrlSegment("skip", skip.ToString());
            request.AddUrlSegment("take", take.ToString());
            request.AddUrlSegment("filter", filter);
            request.AddUrlSegment("userProvider", userProvider);
            request.AddUrlSegment("forAllUserProviders", forAllUserProviders.ToString());

            request.AddParameter("application/json", SerializeObject(localChange), ParameterType.RequestBody);

            return ExecuteRequest<CollectionContext<WcfMembershipUser>>(request);
        }

        //[WebInvoke(Method = "PUT", UriTemplate = "pick/{roleIdString}/?provider={provider}")]
        public CollectionContext<Guid> PickUsersInRole(Guid roleId, string provider, Guid[] userIdsToPickFrom)
        {
            var request = new RestRequest(this.GetServiceUrl("pick/{roleId}/?provider={provider}"), Method.PUT);

            request.AddUrlSegment("roleId", roleId.ToString());
            request.AddUrlSegment("provider", provider);

            request.AddParameter("application/json", SerializeObject(userIdsToPickFrom), ParameterType.RequestBody);

            return ExecuteRequest<CollectionContext<Guid>>(request);
        }

        //[WebInvoke(Method = "PUT", UriTemplate = "{roleId}/?provider={provider}")]
        public WcfRole SaveRole(WcfRole role, Guid roleId, string provider)
        {
            var request = new RestRequest(this.GetServiceUrl("{roleId}/?provider={provider}"), Method.PUT);

            request.AddUrlSegment("roleId", roleId.ToString());
            request.AddUrlSegment("provider", provider);

            request.AddParameter("application/json", SerializeObject(role), ParameterType.RequestBody);

            return ExecuteRequest<WcfRole>(request);
        }

        //[WebInvoke(Method = "PUT", UriTemplate = "SaveRoleUser/{roleId}/?provider={provider}&sortExpression={sortExpression}&skip={skip}&take={take}&filter={filter}")]
        public string SaveRoleUser(UserProviderPair[] users, Guid roleId, string provider, string sortExpression, string skip, string take, string filter)
        {
            var request = new RestRequest(this.GetServiceUrl("SaveRoleUser/{roleId}/?provider={provider}&sortExpression={sortExpression}&skip={skip}&take={take}&filter={filter}"), Method.PUT);

            request.AddUrlSegment("roleId", roleId.ToString());
            request.AddUrlSegment("provider", provider);
            request.AddUrlSegment("sortExpression", sortExpression);
            request.AddUrlSegment("skip", skip);
            request.AddUrlSegment("take", take);
            request.AddUrlSegment("filter", filter);

            request.AddParameter("application/json", SerializeObject(users), ParameterType.RequestBody);

            return ExecuteRequest<string>(request);
        }
    }
}
