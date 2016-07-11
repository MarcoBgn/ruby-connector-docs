class OauthController < ApplicationController

  #BaseClient.authorize instantiates a new BaseCRM::Client instance
  #and queries the API to obtain an authorization code.
  def request_omniauth
    if is_admin
      auth_params = {
        state: current_organization.uid
      }
      client = BaseClient.authorize(QueryParamsManager.query_params(auth_params))
      redirect_to client.auth_code.authorize_url(redirect_uri: BaseClient::RED_URI )
    else
      redirect_to root_url
    end
  end

  #BaseClient.obtain_token is used to create a client with the callback URI set to redirect
  #to the #create_omniauth action. The OrganizationManager service is then used to obtain the token.
  def create_omniauth
    org_uid = params[:state]
    organization = Organization.find_by_uid_and_tenant(org_uid, current_user.tenant)
    if organization && is_admin?(current_user, organization)
      client = BaseClient.obtain_token
      if params[:code].present?
        token = client.auth_code.get_token(params[:code], redirect_uri: BaseClient::RED_URI)
        manager = OrganizationManager.update(organization, token)
      end
    end
    redirect_to root_url
  end

  def destroy_omniauth
    organization = Organization.find_by_id(params[:organization_id])

    if organization && is_admin?(current_user, organization)
      organization.revoke_omniauth
    end

    redirect_to root_url
  end
end
