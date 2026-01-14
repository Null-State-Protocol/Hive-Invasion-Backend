#!/usr/bin/env python3
"""
Migration Script: Verify Existing Users
Sets email_verified=True for all existing users created before email verification was enabled.
"""

import boto3
from datetime import datetime

def migrate_existing_users():
    """Mark all existing users as email verified"""
    
    dynamodb = boto3.resource('dynamodb', region_name='eu-north-1')
    users_table = dynamodb.Table('hive_users')
    
    print("🔍 Scanning for unverified users...")
    
    # Scan for users where email_verified is False or doesn't exist
    response = users_table.scan(
        FilterExpression='attribute_not_exists(email_verified) OR email_verified = :false',
        ExpressionAttributeValues={':false': False}
    )
    
    users = response.get('Items', [])
    total = len(users)
    
    if total == 0:
        print("✅ No users need migration. All users are already verified!")
        return
    
    print(f"📊 Found {total} users to migrate...")
    
    migrated = 0
    failed = 0
    
    for user in users:
        user_id = user.get('user_id')
        email = user.get('email', 'N/A')
        
        try:
            # Update user to verified
            users_table.update_item(
                Key={'user_id': user_id},
                UpdateExpression='SET email_verified = :true, updated_at = :now',
                ExpressionAttributeValues={
                    ':true': True,
                    ':now': datetime.utcnow().isoformat() + 'Z'
                }
            )
            
            migrated += 1
            print(f"  ✓ Verified user: {email} (ID: {user_id[:8]}...)")
            
        except Exception as e:
            failed += 1
            print(f"  ✗ Failed to verify {email}: {str(e)}")
    
    print(f"\n{'='*60}")
    print(f"✅ Migration Complete!")
    print(f"{'='*60}")
    print(f"  Total users processed: {total}")
    print(f"  Successfully migrated: {migrated}")
    print(f"  Failed: {failed}")
    print(f"{'='*60}\n")

if __name__ == "__main__":
    print("="*60)
    print("  MIGRATION: Verify Existing Users")
    print("="*60)
    print("\n⚠️  This will mark all existing users as email verified.")
    print("    New users after this migration will require email verification.\n")
    
    confirm = input("Continue? (yes/no): ").strip().lower()
    
    if confirm == 'yes':
        migrate_existing_users()
    else:
        print("❌ Migration cancelled.")
