#!/usr/bin/env python3
from email.policy import default
import boto3
import click
import json
from pathlib import Path


STAGE_NAME = 'burpendpoint'
API_NAME = 'BurpAPI'
AVAIL_REGIONS = [
	"us-east-1","us-west-1","us-east-2",
	"us-west-2","eu-central-1","eu-west-1",
	"eu-west-2","eu-west-3","sa-east-1","eu-north-1"
]

@click.command()
@click.option('--profile', default="pentest1", help='AWS profile to use', show_default=True)
@click.option('--state-file', default="api_gateways.txt", help='API GW state directory, script creates STATE_FILE and STATE_FILE.json.', show_default=True)
@click.option('--create', default=None, help='specify target URL: https://example.com', show_default=True)
@click.option('--delete', is_flag=True)
def main(profile, create, delete, state_file):

    if create:

        createGw(profile, target_url=create, state_file=state_file)

    if delete:

        deleteGw(profile, state_file)

def createGw(profile, target_url, state_file):
    allEndpoints=[]
    enabled_regions={}

    for region in AVAIL_REGIONS:
        print(f'[ ] {region}')
        session = boto3.session.Session(profile_name=profile, region_name=region)

        awsclient = session.client('apigateway')

        create_api_response = awsclient.create_rest_api(
            name=API_NAME,
            endpointConfiguration={
                'types': [
                    'REGIONAL',
                ]
            }
        )

        get_resource_response = awsclient.get_resources(
            restApiId=create_api_response['id']
        )
        
        restAPIId = create_api_response['id']
        print(f'[ ] create API GW: {restAPIId}')
        
        enabled_regions[region] = restAPIId


        create_resource_response = awsclient.create_resource(
            restApiId=create_api_response['id'],
            parentId=get_resource_response['items'][0]['id'],
            pathPart='{proxy+}'
        )
        
        awsclient.put_method(
            restApiId=create_api_response['id'],
            resourceId=get_resource_response['items'][0]['id'],
            httpMethod='ANY',
            authorizationType='NONE',
            requestParameters={
                'method.request.path.proxy':True,
                'method.request.header.X-My-X-Forwarded-For':True
                            }
        )

        awsclient.put_integration(
            restApiId=create_api_response['id'],
            resourceId=get_resource_response['items'][0]['id'],
            type='HTTP_PROXY',
            httpMethod='ANY',
            integrationHttpMethod='ANY',
            uri=target_url + '/',
            connectionType='INTERNET',
            requestParameters={
                'integration.request.path.proxy':'method.request.path.proxy',
                                    'integration.request.header.X-Forwarded-For': 'method.request.header.X-My-X-Forwarded-For'
            }
        )

        awsclient.put_method(
            restApiId=create_api_response['id'],
            resourceId=create_resource_response['id'],
            httpMethod='ANY',
            authorizationType='NONE',
            requestParameters={
                'method.request.path.proxy':True,
                'method.request.header.X-My-X-Forwarded-For':True
            }
        )

        awsclient.put_integration(
            restApiId=create_api_response['id'],
            resourceId=create_resource_response['id'],
            type= 'HTTP_PROXY', 
            httpMethod= 'ANY',
            integrationHttpMethod='ANY',
            uri= target_url+'/{proxy}',
            connectionType= 'INTERNET',
            requestParameters={
                'integration.request.path.proxy':'method.request.path.proxy',
                                    'integration.request.header.X-Forwarded-For': 'method.request.header.X-My-X-Forwarded-For'
            }
        )

        deploy_response = awsclient.create_deployment(
            restApiId=restAPIId,
            stageName=STAGE_NAME

        )

        allEndpoints.append(restAPIId+'.execute-api.'+region+'.amazonaws.com')
        
        usage_response = awsclient.create_usage_plan(
            name='burpusage',
            description=restAPIId,
            apiStages=[
                {
                'apiId': restAPIId,
                'stage': STAGE_NAME
                }
            ]
        )

    #Print out some info to burp console
    print('Enabled regions')
    print(json.dumps(enabled_regions))
    print( 'List of endpoints being used:')
    print( '\n'.join(allEndpoints))

    with open('{}.json'.format(state_file), 'w') as f:
        json.dump(enabled_regions, f)

    with open(state_file, 'w') as f:
        f.write('\n'.join(allEndpoints))

    return

def deleteGw(profile, state_file):
    with open('{}.json'.format(state_file), 'r') as f:
        enabled_regions=json.load(f)

    if enabled_regions:
        for region in enabled_regions.keys():
            session = boto3.session.Session(profile_name=profile, region_name=region)

            awsclient = session.client('apigateway')

            response = awsclient.delete_rest_api(
                restApiId=enabled_regions[region]
            )
            print(response)
    return

if __name__ == '__main__':

    main()