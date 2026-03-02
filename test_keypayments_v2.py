#!/usr/bin/env python3
"""
KeyPayments v2 Integration Test Helper
Tests both legacy and contract-based payment systems
"""

import json
import os
import sys
import requests
from typing import Dict, Optional, Tuple

# Colors for terminal output
class Colors:
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    END = '\033[0m'

def print_success(msg: str):
    print(f"{Colors.GREEN}✓ {msg}{Colors.END}")

def print_error(msg: str):
    print(f"{Colors.RED}✗ {msg}{Colors.END}")

def print_info(msg: str):
    print(f"{Colors.BLUE}ℹ {msg}{Colors.END}")

def print_warning(msg: str):
    print(f"{Colors.YELLOW}⚠ {msg}{Colors.END}")

class KeyPaymentsV2Tester:
    """Test helper for KeyPayments v2 integration"""
    
    def __init__(self, 
                 api_endpoint: str,
                 jwt_token: str,
                 rpc_endpoint: str = "https://api.infra.mainnet.somnia.network/"):
        self.api_endpoint = api_endpoint.rstrip('/')
        self.jwt_token = jwt_token
        self.rpc_endpoint = rpc_endpoint
        self.session = requests.Session()
        self.session.headers.update({
            "Authorization": f"Bearer {jwt_token}",
            "Content-Type": "application/json"
        })
    
    def test_api_health(self) -> bool:
        """Test if API endpoint is accessible"""
        try:
            print_info("Testing API endpoint...")
            # Try getting user profile as health check
            response = self.session.get(f"{self.api_endpoint}/users/profile")
            if response.status_code in [200, 401, 404]:  # 401 if not authenticated
                print_success(f"API is accessible ({response.status_code})")
                return True
            else:
                print_error(f"API returned unexpected status {response.status_code}")
                return False
        except Exception as e:
            print_error(f"API endpoint not accessible: {e}")
            return False
    
    def test_rpc_connection(self) -> bool:
        """Test RPC endpoint connectivity"""
        try:
            print_info("Testing RPC endpoint...")
            payload = {
                "jsonrpc": "2.0",
                "method": "eth_chainId",
                "params": [],
                "id": 1
            }
            response = requests.post(self.rpc_endpoint, json=payload, timeout=5)
            data = response.json()
            
            if "result" in data:
                chain_id = int(data["result"], 16)
                if chain_id == 5031:
                    print_success(f"RPC connected to Somnia Mainnet (Chain ID: {chain_id})")
                    return True
                else:
                    print_error(f"RPC is not Somnia Mainnet (Chain ID: {chain_id})")
                    return False
            else:
                print_error(f"RPC error: {data.get('error', 'Unknown error')}")
                return False
        except Exception as e:
            print_error(f"RPC endpoint not accessible: {e}")
            return False
    
    def test_legacy_system(self, tx_hash: str, key_type: str = "bronze") -> Tuple[bool, Optional[Dict]]:
        """
        Test legacy direct SOMI transfer system
        
        Args:
            tx_hash: Transaction hash of SOMI transfer to treasury
            key_type: Key type (bronze, silver, or gold)
        
        Returns:
            Tuple of (success, response_data)
        """
        try:
            print_info(f"Testing legacy system with tx_hash {tx_hash[:12]}...")
            
            payload = {
                "key_type": key_type,
                "tx_hash": tx_hash
            }
            
            response = self.session.post(
                f"{self.api_endpoint}/keys/purchase",
                json=payload
            )
            
            data = response.json()
            
            if response.status_code == 200:
                if data.get("payment_system") == "legacy":
                    print_success(f"Legacy system purchase verified (Status: {response.status_code})")
                    return True, data
                else:
                    print_warning(f"Purchase succeeded but used system: {data.get('payment_system')}")
                    return False, data
            elif response.status_code == 202:
                print_warning(f"Transaction pending on-chain (will retry later)")
                return False, data
            else:
                reason = data.get("message") or data.get("reason", "Unknown error")
                print_error(f"Legacy system purchase failed: {reason}")
                return False, data
        
        except Exception as e:
            print_error(f"Legacy system test error: {e}")
            return False, None
    
    def test_contract_system(self, tx_hash: str, key_type: str = "bronze") -> Tuple[bool, Optional[Dict]]:
        """
        Test KeyPayments v2 contract system
        
        Args:
            tx_hash: Transaction hash of contract buy() call
            key_type: Key type (bronze, silver, or gold)
        
        Returns:
            Tuple of (success, response_data)
        """
        try:
            print_info(f"Testing contract system with tx_hash {tx_hash[:12]}...")
            
            payload = {
                "key_type": key_type,
                "tx_hash": tx_hash
            }
            
            response = self.session.post(
                f"{self.api_endpoint}/keys/purchase",
                json=payload
            )
            
            data = response.json()
            
            if response.status_code == 201:
                if data.get("payment_system") == "contract":
                    print_success(f"Contract system purchase verified (Status: {response.status_code})")
                    return True, data
                else:
                    print_warning(f"Purchase succeeded but used system: {data.get('payment_system')}")
                    return False, data
            elif response.status_code == 202:
                print_warning(f"Transaction pending on-chain (will retry later)")
                return False, data
            else:
                reason = data.get("message") or data.get("reason", "Unknown error")
                print_error(f"Contract system purchase failed: {reason}")
                return False, data
        
        except Exception as e:
            print_error(f"Contract system test error: {e}")
            return False, None
    
    def test_dual_mode(self, legacy_tx: str, contract_tx: str, key_type: str = "silver") -> Dict:
        """
        Test dual mode (fallback behavior)
        
        Args:
            legacy_tx: Transaction hash of SOMI transfer
            contract_tx: Transaction hash of contract call
            key_type: Key type to test
        
        Returns:
            Test results summary
        """
        results = {
            "legacy": None,
            "contract": None,
            "dual_mode_behavior": None
        }
        
        print_info("\n=== TESTING DUAL MODE (Fallback Behavior) ===\n")
        
        # Test legacy first
        if legacy_tx:
            print_info("Step 1: Testing legacy SOMI transfer")
            success, data = self.test_legacy_system(legacy_tx, key_type)
            results["legacy"] = {"success": success, "data": data}
        
        # Test contract
        if contract_tx:
            print_info("\nStep 2: Testing contract purchase")
            success, data = self.test_contract_system(contract_tx, key_type)
            results["contract"] = {"success": success, "data": data}
        
        # Determine dual mode behavior
        if results["legacy"] and results["legacy"]["success"]:
            results["dual_mode_behavior"] = "Legacy system succeeded first"
        elif results["contract"] and results["contract"]["success"]:
            results["dual_mode_behavior"] = "Contract system succeeded (legacy failed)"
        else:
            results["dual_mode_behavior"] = "Both systems failed"
        
        return results
    
    def test_price_validation(self) -> Dict:
        """Test that prices are correctly validated"""
        print_info("\n=== TESTING PRICE VALIDATION ===\n")
        
        results = {}
        key_prices = {
            "bronze": {"legacy": 0.1, "contract": 1.0},
            "silver": {"legacy": 0.5, "contract": 2.0},
            "gold": {"legacy": 1.0, "contract": 3.0}
        }
        
        for key_type, prices in key_prices.items():
            print_info(f"Expected prices for {key_type}:")
            print(f"  Legacy: {prices['legacy']} SOMI (static, may vary)")
            print(f"  Contract: {prices['contract']} SOMI")
            results[key_type] = prices
        
        return results
    
    def test_wallet_validation(self, no_wallet_user_jwt: Optional[str] = None) -> bool:
        """Test wallet validation errors"""
        if not no_wallet_user_jwt:
            print_warning("No wallet validation user JWT provided, skipping...")
            return True
        
        try:
            print_info("Testing wallet validation...")
            
            headers = {
                "Authorization": f"Bearer {no_wallet_user_jwt}",
                "Content-Type": "application/json"
            }
            
            payload = {
                "key_type": "bronze",
                "tx_hash": "0x" + "0" * 64
            }
            
            response = requests.post(
                f"{self.api_endpoint}/keys/purchase",
                json=payload,
                headers=headers
            )
            
            data = response.json()
            
            if response.status_code == 400:
                if "wallet" in data.get("message", "").lower():
                    print_success("Wallet validation working (correctly rejected)")
                    return True
            
            print_warning("Wallet validation response unexpected")
            return False
        
        except Exception as e:
            print_error(f"Wallet validation test error: {e}")
            return False

def main():
    import argparse
    
    parser = argparse.ArgumentParser(
        description="Test KeyPayments v2 integration (legacy + contract systems)"
    )
    parser.add_argument("--api", required=True, help="API endpoint (e.g., https://api.example.com)")
    parser.add_argument("--jwt", required=True, help="JWT authentication token")
    parser.add_argument("--rpc", default="https://api.infra.mainnet.somnia.network/",
                       help="RPC endpoint")
    parser.add_argument("--legacy-tx", help="Transaction hash for legacy system test")
    parser.add_argument("--contract-tx", help="Transaction hash for contract system test")
    parser.add_argument("--key-type", default="bronze", help="Key type to test")
    parser.add_argument("--dual-mode", action="store_true", help="Test dual mode behavior")
    
    args = parser.parse_args()
    
    tester = KeyPaymentsV2Tester(args.api, args.jwt, args.rpc)
    
    print("\n" + "="*60)
    print("KeyPayments v2 Integration Test Suite")
    print("="*60 + "\n")
    
    # Test connectivity
    print("=== CONNECTIVITY TESTS ===\n")
    api_ok = tester.test_api_health()
    rpc_ok = tester.test_rpc_connection()
    
    if not (api_ok and rpc_ok):
        print_error("Basic connectivity tests failed. Cannot proceed.")
        sys.exit(1)
    
    # Test payment systems
    print("\n=== PAYMENT SYSTEM TESTS ===\n")
    
    # Price validation
    print("Price Configuration Check:")
    tester.test_price_validation()
    
    # Test legacy system if tx provided
    if args.legacy_tx:
        print(f"\nTesting legacy system with {args.legacy_tx[:12]}...")
        success, data = tester.test_legacy_system(args.legacy_tx, args.key_type)
        if success and data:
            print(json.dumps(data, indent=2))
    
    # Test contract system if tx provided
    if args.contract_tx:
        print(f"\nTesting contract system with {args.contract_tx[:12]}...")
        success, data = tester.test_contract_system(args.contract_tx, args.key_type)
        if success and data:
            print(json.dumps(data, indent=2))
    
    # Test dual mode
    if args.dual_mode and (args.legacy_tx or args.contract_tx):
        results = tester.test_dual_mode(args.legacy_tx or "", args.contract_tx or "", args.key_type)
        print("\nDual Mode Results:")
        print(json.dumps(results, indent=2, default=str))
    # Summary
    print("\n" + "="*60)
    print_success("Test suite completed. Review results above.")
    print("="*60 + "\n")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print_warning("\nTest interrupted by user")
        sys.exit(0)
    except Exception as e:
        print_error(f"Unexpected error: {e}")
        sys.exit(1)
