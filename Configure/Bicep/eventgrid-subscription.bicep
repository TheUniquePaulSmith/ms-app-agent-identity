// Event Grid push subscription: agent.lifecycle topic -> kill switch webhook.
// Deployed AFTER the kill switch code is running: Event Grid sends the
// CloudEvents validation handshake (HTTP OPTIONS) when the subscription is created.

param topicName string
param killSwitchHost string
param storageAccountName string

@secure()
param internalKey string

resource topic 'Microsoft.EventGrid/topics@2025-02-15' existing = {
  name: topicName
}

resource storage 'Microsoft.Storage/storageAccounts@2024-01-01' existing = {
  name: storageAccountName
}

resource subscription 'Microsoft.EventGrid/topics/eventSubscriptions@2025-02-15' = {
  parent: topic
  name: 'to-killswitch'
  properties: {
    destination: {
      endpointType: 'WebHook'
      properties: {
        endpointUrl: 'https://${killSwitchHost}/events?code=${internalKey}'
        maxEventsPerBatch: 1
        preferredBatchSizeInKilobytes: 64
      }
    }
    eventDeliverySchema: 'CloudEventSchemaV1_0'
    filter: {
      includedEventTypes: [ 'Poc.Agent.Killed', 'Poc.Agent.Restored' ]
    }
    retryPolicy: {
      maxDeliveryAttempts: 10
      eventTimeToLiveInMinutes: 60
    }
    deadLetterDestination: {
      endpointType: 'StorageBlob'
      properties: {
        resourceId: storage.id
        blobContainerName: 'deadletter'
      }
    }
  }
}

output subscriptionName string = subscription.name
