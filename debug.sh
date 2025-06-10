#!/bin/bash

if [ -z "$1" ]; then
  echo "Usage: $0 <cluster-name-fragment>"
  exit 1
fi

SEARCH="$1"

CLUSTER=$(aws ecs list-clusters --profile sso \
  --query "clusterArns[?contains(@, '$SEARCH')]" --output text | head -n 1)

if [ -z "$CLUSTER" ] || [ "$CLUSTER" = "None" ]; then
  echo "No cluster found matching '$SEARCH'. Available clusters:"
  aws ecs list-clusters --profile sso
  exit 1
fi

SERVICE=$(aws ecs list-services --cluster "$CLUSTER" --profile sso \
  --query "serviceArns[0]" --output text)

TASK=$(aws ecs list-tasks --cluster "$CLUSTER" --service-name "$SERVICE" --profile sso \
  --query "taskArns[0]" --output text)

CONTAINER=$(aws ecs describe-tasks --cluster "$CLUSTER" --tasks "$TASK" --profile sso \
  --query "tasks[0].containers[0].name" --output text)

echo "Connecting to cluster=$CLUSTER"
echo "Service: $SERVICE"
echo "Task: $TASK"
echo "Container: $CONTAINER"

aws ecs execute-command \
  --cluster "$CLUSTER" \
  --task "$TASK" \
  --container "$CONTAINER" \
  --command "/bin/sh" \
  --interactive \
  --profile sso
