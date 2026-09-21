from flask import Flask, request, jsonify, send_from_directory
import boto3
import logging

app = Flask(__name__)
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Serve HTML form
@app.route('/')
def serve_form():
    return send_from_directory('/var/www/html', 'index.html')


# STS Assume Role Helper
# Uses the purpose-scoped Route 53 zone-sharing role (deployed org-wide via StackSet).
def assume_role(account_id, role_name="CsaaRoute53ZoneSharingRole"):
    sts_client = boto3.client("sts")
    try:
        response = sts_client.assume_role(
            RoleArn=f"arn:aws:iam::{account_id}:role/{role_name}",
            RoleSessionName="assume-role-session",
            DurationSeconds=900
        )
        return response["Credentials"]
    except Exception as e:
        logger.error(f"Failed to assume role for account {account_id}: {e}")
        raise


# API route to process Hosted Zone association
@app.route('/create-vpc-association', methods=['POST'])
def create_vpc_association():
    try:
        ss_account = request.form.get('ss_account')
        requesting_account = request.form.get('requesting_account')
        region = request.form.get('aws_region')
        vpc_id = request.form.get('vpc_id')
        hosted_zone_id = request.form.get('hosted_zone_id')

        if not all([ss_account, requesting_account, region, vpc_id, hosted_zone_id]):
            return jsonify({"error": "Missing required form fields."}), 400

        # Assume role into shared services account
        ss_creds = assume_role(ss_account)
        ss_route53 = boto3.client(
            "route53",
            region_name=region,
            aws_access_key_id=ss_creds["AccessKeyId"],
            aws_secret_access_key=ss_creds["SecretAccessKey"],
            aws_session_token=ss_creds["SessionToken"]
        )
        auth_response = ss_route53.create_vpc_association_authorization(
            HostedZoneId=hosted_zone_id,
            VPC={
                'VPCRegion': region,
                'VPCId': vpc_id
            }
        )

        # Assume role into requesting account
        req_creds = assume_role(requesting_account)
        req_route53 = boto3.client(
            "route53",
            region_name=region,
            aws_access_key_id=req_creds["AccessKeyId"],
            aws_secret_access_key=req_creds["SecretAccessKey"],
            aws_session_token=req_creds["SessionToken"]
        )
        assoc_response = req_route53.associate_vpc_with_hosted_zone(
            HostedZoneId=hosted_zone_id,
            VPC={
                'VPCRegion': region,
                'VPCId': vpc_id
            }
        )

        # Clean up the authorization
        delete_auth = ss_route53.delete_vpc_association_authorization(
            HostedZoneId=hosted_zone_id,
            VPC={
                'VPCRegion': region,
                'VPCId': vpc_id
            }
        )

        return jsonify({
            "authorization": auth_response,
            "association": assoc_response,
            "auth_cleanup": delete_auth
        }), 200

    except Exception as e:
        logger.exception("Error processing VPC association")
        return jsonify({"error": str(e)}), 500


# Run the app. Bind to loopback only -- nginx fronts it at /zone-sharing/.
# (debug disabled for a shared/production host.)
if __name__ == '__main__':
    app.run(host='127.0.0.1', port=8080)