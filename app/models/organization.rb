class Organization < Maestrano::Connector::Rails::Organization

  def revoke_omniauth
    self.oauth_uid = nil
    self.oauth_token = nil
    self.refresh_token = nil
    self.sync_enabled = false
    self.oauth_provider = nil
    self.save
  end
  # --------------------------------------------
  #             Overloaded methods
  # --------------------------------------------
  def from_omniauth(auth)
    self.oauth_uid = "baseCRM-001"
    self.oauth_token = auth.token
    self.refresh_token = auth.refresh_token
    self.oauth_provider = 'Base'
    self.save
  end
end
