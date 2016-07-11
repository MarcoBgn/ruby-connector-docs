class Entities::SubEntities::Contact < Maestrano::Connector::Rails::SubEntityBase

  def self.external?
    true
  end

  def self.entity_name
    'Contact'
  end

  def self.mapper_classes
    {
      'Person' => Entities::SubEntities::PersonMapper,
      'Organization' => Entities::SubEntities::OrganizationMapper
    }
  end

  #The name is chosen conditionally. Companies have the mandatory field name, while
  #People can just have first_name and/or last_name
  def self.object_name_from_external_entity_hash(entity)
    if entity['data']['is_organization']
      "#{entity['data']['name']}"
    else
      "#{entity['data']['first_name']} #{entity['data']['last_name']}"
    end
  end
end
