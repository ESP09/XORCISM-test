import type { StudioConfig } from '../../shared/config.js';
import { oidcHost, type FileMap } from './util.js';

export function cfnFiles(c: StudioConfig): FileMap {
  const f: FileMap = {};
  f['cloudformation/intake-bucket.yaml'] = `AWSTemplateFormatVersion: "2010-09-09"
Description: >-
  DefectDojo GovCloud - SSE-KMS S3 intake bucket (scanner reports / office submissions) and state bucket
  (threat-feed snapshots, fingerprints, metrics history). TLS-only, KMS-only, private, versioned, logged.
  NIST SP 800-171: 3.1.3, 3.3.1, 3.8.9, 3.13.8, 3.13.11, 3.13.16.

Parameters:
  IntakeBucketName: { Type: String, Default: ${c.aws.intakeBucket} }
  StateBucketName: { Type: String, Default: ${c.aws.stateBucket} }
  KmsAliasName: { Type: String, Default: ${c.aws.kmsKeyAlias} }
  AutomationRoleName: { Type: String, Default: ${c.project.name}-automation }
  VpcEndpointId:
    Type: String
    Default: ""
    Description: Optional S3 gateway/interface endpoint id; when set, bucket access is restricted to it.
  IntakeRetentionDays: { Type: Number, Default: 90 }

Conditions:
  RestrictToVpce: !Not [!Equals [!Ref VpcEndpointId, ""]]

Resources:
  DataKey:
    Type: AWS::KMS::Key
    Properties:
      Description: DefectDojo intake/state encryption key
      EnableKeyRotation: true
      KeySpec: SYMMETRIC_DEFAULT
      KeyPolicy:
        Version: "2012-10-17"
        Statement:
          - Sid: AccountAdmin
            Effect: Allow
            Principal: { AWS: !Sub "arn:\${AWS::Partition}:iam::\${AWS::AccountId}:root" }
            Action: "kms:*"
            Resource: "*"
          - Sid: AutomationUse
            Effect: Allow
            Principal: { AWS: !Sub "arn:\${AWS::Partition}:iam::\${AWS::AccountId}:role/\${AutomationRoleName}" }
            Action: ["kms:Decrypt", "kms:GenerateDataKey", "kms:DescribeKey"]
            Resource: "*"
            Condition:
              StringEquals:
                kms:ViaService: !Sub "s3.\${AWS::Region}.amazonaws.com"

  DataKeyAlias:
    Type: AWS::KMS::Alias
    Properties:
      AliasName: !Ref KmsAliasName
      TargetKeyId: !Ref DataKey

  AccessLogBucket:
    Type: AWS::S3::Bucket
    DeletionPolicy: Retain
    Properties:
      BucketName: !Sub "\${IntakeBucketName}-access-logs"
      OwnershipControls: { Rules: [{ ObjectOwnership: BucketOwnerEnforced }] }
      PublicAccessBlockConfiguration: { BlockPublicAcls: true, BlockPublicPolicy: true, IgnorePublicAcls: true, RestrictPublicBuckets: true }
      BucketEncryption:
        ServerSideEncryptionConfiguration:
          - ServerSideEncryptionByDefault: { SSEAlgorithm: AES256 }   # S3 server access logging requires SSE-S3
      VersioningConfiguration: { Status: Enabled }
      LifecycleConfiguration:
        Rules: [{ Id: expire-logs, Status: Enabled, ExpirationInDays: 365 }]

  AccessLogBucketPolicy:
    Type: AWS::S3::BucketPolicy
    Properties:
      Bucket: !Ref AccessLogBucket
      PolicyDocument:
        Version: "2012-10-17"
        Statement:
          - Sid: S3ServerAccessLogs
            Effect: Allow
            Principal: { Service: logging.s3.amazonaws.com }
            Action: s3:PutObject
            Resource: !Sub "\${AccessLogBucket.Arn}/*"
            Condition: { StringEquals: { aws:SourceAccount: !Ref AWS::AccountId } }
          - Sid: DenyInsecureTransport
            Effect: Deny
            Principal: "*"
            Action: "s3:*"
            Resource: [!GetAtt AccessLogBucket.Arn, !Sub "\${AccessLogBucket.Arn}/*"]
            Condition: { Bool: { aws:SecureTransport: "false" } }

${['Intake', 'State'].map(kind => `  ${kind}Bucket:
    Type: AWS::S3::Bucket
    DeletionPolicy: Retain
    UpdateReplacePolicy: Retain
    Properties:
      BucketName: !Ref ${kind}BucketName
      OwnershipControls: { Rules: [{ ObjectOwnership: BucketOwnerEnforced }] }
      PublicAccessBlockConfiguration: { BlockPublicAcls: true, BlockPublicPolicy: true, IgnorePublicAcls: true, RestrictPublicBuckets: true }
      BucketEncryption:
        ServerSideEncryptionConfiguration:
          - ServerSideEncryptionByDefault:
              SSEAlgorithm: aws:kms
              KMSMasterKeyID: !GetAtt DataKey.Arn
            BucketKeyEnabled: true
      VersioningConfiguration: { Status: Enabled }
      LoggingConfiguration:
        DestinationBucketName: !Ref AccessLogBucket
        LogFilePrefix: ${kind.toLowerCase()}/
      LifecycleConfiguration:
        Rules:
${kind === 'Intake' ? `          - { Id: processed-expiry, Status: Enabled, Prefix: processed/, ExpirationInDays: !Ref IntakeRetentionDays }
          - { Id: rejected-expiry, Status: Enabled, Prefix: rejected/, ExpirationInDays: !Ref IntakeRetentionDays }
          - { Id: abort-mpu, Status: Enabled, AbortIncompleteMultipartUpload: { DaysAfterInitiation: 2 } }
          - { Id: noncurrent, Status: Enabled, NoncurrentVersionExpiration: { NoncurrentDays: 30 } }` : `          - { Id: snapshot-tiering, Status: Enabled, Prefix: feeds/snapshots/, Transitions: [{ StorageClass: STANDARD_IA, TransitionInDays: 30 }], ExpirationInDays: 400 }
          - { Id: noncurrent, Status: Enabled, NoncurrentVersionExpiration: { NoncurrentDays: 90 } }`}

  ${kind}BucketPolicy:
    Type: AWS::S3::BucketPolicy
    Properties:
      Bucket: !Ref ${kind}Bucket
      PolicyDocument:
        Version: "2012-10-17"
        Statement:
          - Sid: DenyInsecureTransport
            Effect: Deny
            Principal: "*"
            Action: "s3:*"
            Resource: [!GetAtt ${kind}Bucket.Arn, !Sub "\${${kind}Bucket.Arn}/*"]
            Condition: { Bool: { aws:SecureTransport: "false" } }
          - Sid: DenyOldTls
            Effect: Deny
            Principal: "*"
            Action: "s3:*"
            Resource: [!GetAtt ${kind}Bucket.Arn, !Sub "\${${kind}Bucket.Arn}/*"]
            Condition: { NumericLessThan: { s3:TlsVersion: "1.2" } }
          - Sid: DenyNonKmsEncryption
            Effect: Deny
            Principal: "*"
            Action: s3:PutObject
            Resource: !Sub "\${${kind}Bucket.Arn}/*"
            Condition: { StringNotEqualsIfExists: { s3:x-amz-server-side-encryption: aws:kms } }
          - Sid: DenyWrongKmsKey
            Effect: Deny
            Principal: "*"
            Action: s3:PutObject
            Resource: !Sub "\${${kind}Bucket.Arn}/*"
            Condition:
              StringNotEqualsIfExists: { s3:x-amz-server-side-encryption-aws-kms-key-id: !GetAtt DataKey.Arn }
              "Null": { s3:x-amz-server-side-encryption-aws-kms-key-id: "false" }
          - !If
            - RestrictToVpce
            - Sid: DenyOutsideVpce
              Effect: Deny
              Principal: "*"
              Action: "s3:*"
              Resource: [!GetAtt ${kind}Bucket.Arn, !Sub "\${${kind}Bucket.Arn}/*"]
              Condition:
                StringNotEquals: { aws:SourceVpce: !Ref VpcEndpointId }
                ArnNotLike: { aws:PrincipalArn: !Sub "arn:\${AWS::Partition}:iam::\${AWS::AccountId}:role/*admin*" }
            - !Ref AWS::NoValue
`).join('\n')}
Outputs:
  IntakeBucketArn: { Value: !GetAtt IntakeBucket.Arn, Export: { Name: !Sub "\${AWS::StackName}-IntakeBucketArn" } }
  StateBucketArn: { Value: !GetAtt StateBucket.Arn, Export: { Name: !Sub "\${AWS::StackName}-StateBucketArn" } }
  DataKeyArn: { Value: !GetAtt DataKey.Arn, Export: { Name: !Sub "\${AWS::StackName}-DataKeyArn" } }
`;
  const host = oidcHost(c);
  const gitlabHost = c.gitlab.url.replace(/^https?:\/\//, '').replace(/\/$/, '');
  f['cloudformation/iam-roles.yaml'] = `AWSTemplateFormatVersion: "2010-09-09"
Description: >-
  Least-privilege IAM roles: IRSA for automation CronJobs and External Secrets Operator, and GitLab OIDC
  for CI jobs (no long-lived keys anywhere; no secrets in GitLab CI/CD variables).

Parameters:
  BucketStackName: { Type: String, Default: ${c.project.name}-buckets }
  EksOidcProviderArn: { Type: String, Default: ${c.aws.oidcProviderArn} }
  GitLabOidcProviderArn: { Type: String, Default: "arn:${c.aws.partition}:iam::${c.aws.accountId}:oidc-provider/${gitlabHost}" }
  SecretsPrefix: { Type: String, Default: ${c.aws.secretsPrefix} }
  EnableSes: { Type: String, AllowedValues: ["true", "false"], Default: "${c.notifications.transport === 'ses'}" }

Conditions:
  UseSes: !Equals [!Ref EnableSes, "true"]

Resources:
  AutomationRole:
    Type: AWS::IAM::Role
    Properties:
      RoleName: ${c.project.name}-automation
      MaxSessionDuration: 3600
      AssumeRolePolicyDocument:
        Version: "2012-10-17"
        Statement:
          - Effect: Allow
            Principal: { Federated: !Ref EksOidcProviderArn }
            Action: sts:AssumeRoleWithWebIdentity
            Condition:
              StringEquals:
                # CloudFormation does not allow intrinsic functions as map keys, so the host is rendered literally.
                "${host}:sub": "system:serviceaccount:${c.kubernetes.namespace}:${c.kubernetes.automationServiceAccount}"
                "${host}:aud": sts.amazonaws.com
      Policies:
        - PolicyName: intake-state
          PolicyDocument:
            Version: "2012-10-17"
            Statement:
              - Effect: Allow
                Action: ["s3:ListBucket"]
                Resource:
                  - { "Fn::ImportValue": !Sub "\${BucketStackName}-IntakeBucketArn" }
                  - { "Fn::ImportValue": !Sub "\${BucketStackName}-StateBucketArn" }
              - Effect: Allow
                Action: ["s3:GetObject", "s3:PutObject", "s3:DeleteObject"]
                Resource:
                  - !Sub ["\${Arn}/*", { Arn: { "Fn::ImportValue": !Sub "\${BucketStackName}-IntakeBucketArn" } }]
                  - !Sub ["\${Arn}/*", { Arn: { "Fn::ImportValue": !Sub "\${BucketStackName}-StateBucketArn" } }]
              - Effect: Allow
                Action: ["kms:Decrypt", "kms:GenerateDataKey", "kms:DescribeKey"]
                Resource: { "Fn::ImportValue": !Sub "\${BucketStackName}-DataKeyArn" }
              - !If
                - UseSes
                - Effect: Allow
                  Action: ["ses:SendEmail", "ses:SendRawEmail"]
                  Resource: "*"
                  Condition: { StringEquals: { ses:FromAddress: ${c.notifications.from} } }
                - !Ref AWS::NoValue

  ExternalSecretsRole:
    Type: AWS::IAM::Role
    Properties:
      RoleName: ${c.project.name}-external-secrets
      AssumeRolePolicyDocument:
        Version: "2012-10-17"
        Statement:
          - Effect: Allow
            Principal: { Federated: !Ref EksOidcProviderArn }
            Action: sts:AssumeRoleWithWebIdentity
            Condition:
              StringEquals:
                "${host}:sub": "system:serviceaccount:${c.kubernetes.namespace}:external-secrets-dojo"
                "${host}:aud": sts.amazonaws.com
      Policies:
        - PolicyName: read-dojo-secrets
          PolicyDocument:
            Version: "2012-10-17"
            Statement:
              - Effect: Allow
                Action: ["secretsmanager:GetSecretValue", "secretsmanager:DescribeSecret"]
                Resource: !Sub "arn:\${AWS::Partition}:secretsmanager:\${AWS::Region}:\${AWS::AccountId}:secret:\${SecretsPrefix}*"
              - Effect: Allow
                Action: ["kms:Decrypt"]
                Resource: "*"
                Condition: { StringEquals: { kms:ViaService: !Sub "secretsmanager.\${AWS::Region}.amazonaws.com" } }

  GitLabCiRole:
    Type: AWS::IAM::Role
    Properties:
      RoleName: gitlab-defectdojo-ci
      MaxSessionDuration: 3600
      AssumeRolePolicyDocument:
        Version: "2012-10-17"
        Statement:
          - Effect: Allow
            Principal: { Federated: !Ref GitLabOidcProviderArn }
            Action: sts:AssumeRoleWithWebIdentity
            Condition:
              StringEquals:
                "${gitlabHost}:aud": "https://${gitlabHost}"
              StringLike:
                "${gitlabHost}:sub": "project_path:${c.gitlab.projectPath}:ref_type:*:ref:*"
      Policies:
        - PolicyName: ci-scoped
          PolicyDocument:
            Version: "2012-10-17"
            Statement:
              - Effect: Allow
                Action: ["secretsmanager:GetSecretValue"]
                Resource: !Sub "arn:\${AWS::Partition}:secretsmanager:\${AWS::Region}:\${AWS::AccountId}:secret:\${SecretsPrefix}ci-*"
              - Effect: Allow
                Action: ["s3:PutObject", "s3:GetObject", "s3:ListBucket"]
                Resource:
                  - { "Fn::ImportValue": !Sub "\${BucketStackName}-StateBucketArn" }
                  - !Sub ["\${Arn}/feeds/*", { Arn: { "Fn::ImportValue": !Sub "\${BucketStackName}-StateBucketArn" } }]
                  - !Sub ["\${Arn}/automation-state/metrics/*", { Arn: { "Fn::ImportValue": !Sub "\${BucketStackName}-StateBucketArn" } }]
              - Effect: Allow
                Action: ["kms:Decrypt", "kms:GenerateDataKey"]
                Resource: { "Fn::ImportValue": !Sub "\${BucketStackName}-DataKeyArn" }
              - Effect: Allow
                Action: ["cloudformation:ValidateTemplate"]
                Resource: "*"

Outputs:
  AutomationRoleArn: { Value: !GetAtt AutomationRole.Arn }
  ExternalSecretsRoleArn: { Value: !GetAtt ExternalSecretsRole.Arn }
  GitLabCiRoleArn: { Value: !GetAtt GitLabCiRole.Arn }
`;
  return f;
}
