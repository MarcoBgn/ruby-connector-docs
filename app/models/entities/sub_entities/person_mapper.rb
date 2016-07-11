class Entities::SubEntities::PersonMapper
  extend HashMapper

  map from('updated_at'), to('data/updated_at')
  map from('created_at'), to('data/created_at')
  map from('title'), to('data/title')
  map from('first_name'), to('data/first_name')
  map from('last_name'), to('data/last_name')
  map from('email/address'), to('data/email')

  map from('address_work/billing/line1'), to('data/address/line1')
  map from('address_work/billing/city'), to('data/address/city')
  map from('address_work/billing/postal_code'), to('data/address/postal_code')
  map from('address_work/billing/country'), to('data/address/country')

  map from('/status'), to('/customer_status')
end
