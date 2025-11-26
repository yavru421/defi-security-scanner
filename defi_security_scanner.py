#!/usr/bin/env python3
"""
DeFi Security Scanner - Commercial Security Analysis Tool
Monetizable service for automated DeFi protocol vulnerability detection
"""

import os
import sys
import json
import time
import asyncio
import logging
from typing import Dict, List, Any, Optional
from datetime import datetime
import requests
import web3
from web3 import Web3

# APT Strict Mode - Fatal error handling
import strict_mode  # noqa: F401

class DeFiSecurityScanner:
    """Commercial DeFi security scanning service"""

    def __init__(self):
        self.logger = logging.getLogger("DeFiSecurityScanner")
        self.logger.setLevel(logging.INFO)
        handler = logging.StreamHandler()
        formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        handler.setFormatter(formatter)
        self.logger.addHandler(handler)

        # Initialize Web3 connections
        infura_key = os.getenv('INFURA_API_KEY')
        infura_url = os.getenv('INFURA_HTTPS')

        # Fallback to config file if environment variables not set
        if not infura_key or not infura_url:
            try:
                import configparser
                config = configparser.ConfigParser()
                config.read('config.ini')
                if 'infura' in config:
                    infura_key = config['infura'].get('api_key', infura_key)
                    infura_url = config['infura'].get('https_url', infura_url)
            except:
                pass

        if not infura_key or not infura_url:
            self.logger.warning("Infura API key not found in environment variables or config file. Using demo mode.")
            self.w3 = None  # Demo mode
        else:
            self.w3 = Web3(Web3.HTTPProvider(infura_url))
            if not self.w3.is_connected():
                self.logger.error("Failed to connect to Infura. Check API key and network.")
                self.w3 = None
        self.scan_results = {}
        self.threat_database = self._load_threat_database()

    def _load_threat_database(self) -> Dict[str, Any]:
        """Load known threat patterns and malicious addresses"""
        return {
            "known_drain_addresses": [
                "0x8d3717281C2Fb7aE5dA9a937eC4f3E0aC1EfA096",  # From yieldlchain scam
                # Add more known malicious addresses
            ],
            "suspicious_patterns": [
                "permit.*unlimited",
                "approve.*max",
                "transferFrom.*balanceOf"
            ],
            "high_risk_functions": [
                "permit",
                "approve",
                "transferFrom",
                "selfdestruct"
            ]
        }

    async def scan_protocol(self, protocol_address: str, protocol_name: str) -> Dict[str, Any]:
        """Comprehensive security scan of a DeFi protocol"""
        self.logger.info(f"Starting security scan for {protocol_name} at {protocol_address}")

        results = {
            "protocol": protocol_name,
            "address": protocol_address,
            "scan_timestamp": datetime.now().isoformat(),
            "risk_score": 0,
            "findings": [],
            "recommendations": []
        }

        try:
            # Check if address is in threat database
            if protocol_address.lower() in [addr.lower() for addr in self.threat_database["known_drain_addresses"]]:
                results["findings"].append({
                    "severity": "CRITICAL",
                    "type": "Known Malicious Address",
                    "description": f"Address {protocol_address} is in known malicious address database",
                    "risk_score": 100
                })
                results["risk_score"] = 100

            # Analyze contract bytecode
            contract_analysis = await self._analyze_contract_bytecode(protocol_address)
            results["findings"].extend(contract_analysis["findings"])
            results["risk_score"] = max(results["risk_score"], contract_analysis["risk_score"])

            # Check for ERC-20 permit vulnerabilities
            permit_analysis = await self._analyze_permit_vulnerabilities(protocol_address)
            results["findings"].extend(permit_analysis["findings"])
            results["risk_score"] = max(results["risk_score"], permit_analysis["risk_score"])

            # Generate recommendations
            results["recommendations"] = self._generate_recommendations(results["findings"])

        except Exception as e:
            self.logger.error(f"Error scanning protocol {protocol_name}: {e}")
            results["findings"].append({
                "severity": "ERROR",
                "type": "Scan Error",
                "description": f"Failed to complete scan: {str(e)}",
                "risk_score": 50
            })

        self.scan_results[protocol_address] = results
        return results

    async def _analyze_contract_bytecode(self, address: str) -> Dict[str, Any]:
        """Analyze contract bytecode for security issues"""
        findings = []
        risk_score = 0

        if not self.w3:
            findings.append({
                "severity": "INFO",
                "type": "Demo Mode",
                "description": "Bytecode analysis requires Infura API key configuration",
                "risk_score": 0
            })
            return {"findings": findings, "risk_score": risk_score}

        try:
            # Get contract code
            code = self.w3.eth.get_code(Web3.to_checksum_address(address))

            if code == b'\x00':  # No code = externally owned account
                return {"findings": findings, "risk_score": risk_score}

            # Convert to hex string for analysis
            bytecode_hex = code.hex()

            # Check for high-risk opcodes
            if 'ff' in bytecode_hex:  # SELFDESTRUCT
                findings.append({
                    "severity": "HIGH",
                    "type": "Self-Destruct Capability",
                    "description": "Contract contains self-destruct functionality",
                    "risk_score": 80
                })
                risk_score = max(risk_score, 80)

            # Check for delegatecall usage (potential reentrancy)
            if 'f4' in bytecode_hex:  # DELEGATECALL
                findings.append({
                    "severity": "MEDIUM",
                    "type": "Delegate Call Usage",
                    "description": "Contract uses delegatecall - check for reentrancy vulnerabilities",
                    "risk_score": 60
                })
                risk_score = max(risk_score, 60)

        except Exception as e:
            findings.append({
                "severity": "ERROR",
                "type": "Bytecode Analysis Error",
                "description": f"Failed to analyze bytecode: {str(e)}",
                "risk_score": 30
            })
            risk_score = max(risk_score, 30)

        return {"findings": findings, "risk_score": risk_score}

    async def _analyze_permit_vulnerabilities(self, address: str) -> Dict[str, Any]:
        """Analyze ERC-20 permit implementation for vulnerabilities"""
        findings = []
        risk_score = 0

        if not self.w3:
            findings.append({
                "severity": "INFO",
                "type": "Demo Mode",
                "description": "Permit analysis requires Infura API key configuration",
                "risk_score": 0
            })
            return {"findings": findings, "risk_score": risk_score}

        try:
            # Check if contract supports ERC-20 interface
            erc20_abi = [
                {"constant": True, "inputs": [], "name": "name", "outputs": [{"name": "", "type": "string"}], "type": "function"},
                {"constant": True, "inputs": [], "name": "symbol", "outputs": [{"name": "", "type": "string"}], "type": "function"},
                {"constant": True, "inputs": [], "name": "decimals", "outputs": [{"name": "", "type": "uint8"}], "type": "function"},
                {"constant": True, "inputs": [], "name": "totalSupply", "outputs": [{"name": "", "type": "uint256"}], "type": "function"},
                {"constant": True, "inputs": [{"name": "_owner", "type": "address"}], "name": "balanceOf", "outputs": [{"name": "balance", "type": "uint256"}], "type": "function"},
                {"constant": True, "inputs": [{"name": "_owner", "type": "address"}, {"name": "_spender", "type": "address"}], "name": "allowance", "outputs": [{"name": "", "type": "uint256"}], "type": "function"},
                {"constant": False, "inputs": [{"name": "_spender", "type": "address"}, {"name": "_value", "type": "uint256"}], "name": "approve", "outputs": [{"name": "", "type": "bool"}], "type": "function"},
                {"constant": False, "inputs": [{"name": "_from", "type": "address"}, {"name": "_to", "type": "address"}, {"name": "_value", "type": "uint256"}], "name": "transferFrom", "outputs": [{"name": "", "type": "bool"}], "type": "function"},
                {"constant": False, "inputs": [{"name": "_to", "type": "address"}, {"name": "_value", "type": "uint256"}], "name": "transfer", "outputs": [{"name": "", "type": "bool"}], "type": "function"}
            ]

            contract = self.w3.eth.contract(address=Web3.to_checksum_address(address), abi=erc20_abi)

            # Try to call name() to verify it's an ERC-20
            try:
                name = contract.functions.name().call()
                self.logger.info(f"Confirmed ERC-20 token: {name}")
            except:
                # Not an ERC-20 token
                return {"findings": findings, "risk_score": risk_score}

            # Check for permit function (ERC-2612)
            permit_abi = [
                {
                    "inputs": [
                        {"internalType": "address", "name": "owner", "type": "address"},
                        {"internalType": "address", "name": "spender", "type": "address"},
                        {"internalType": "uint256", "name": "value", "type": "uint256"},
                        {"internalType": "uint256", "name": "deadline", "type": "uint256"},
                        {"internalType": "uint8", "name": "v", "type": "uint8"},
                        {"internalType": "bytes32", "name": "r", "type": "bytes32"},
                        {"internalType": "bytes32", "name": "s", "type": "bytes32"}
                    ],
                    "name": "permit",
                    "outputs": [],
                    "stateMutability": "nonpayable",
                    "type": "function"
                }
            ]

            permit_contract = self.w3.eth.contract(address=Web3.to_checksum_address(address), abi=permit_abi)

            # Try to call permit function signature check
            try:
                # This will fail but tells us if the function exists
                permit_contract.functions.permit(
                    "0x0000000000000000000000000000000000000000",
                    "0x0000000000000000000000000000000000000000",
                    0, 0, 0, b'\x00' * 32, b'\x00' * 32
                ).call()
            except Exception as e:
                if "execution reverted" not in str(e).lower():
                    # Function exists
                    findings.append({
                        "severity": "MEDIUM",
                        "type": "ERC-2612 Permit Support",
                        "description": "Contract supports ERC-2612 permit function - verify implementation security",
                        "risk_score": 40
                    })
                    risk_score = max(risk_score, 40)

        except Exception as e:
            self.logger.error(f"Error analyzing permit vulnerabilities: {e}")

        return {"findings": findings, "risk_score": risk_score}

    def _generate_recommendations(self, findings: List[Dict[str, Any]]) -> List[str]:
        """Generate security recommendations based on findings"""
        recommendations = []

        severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}

        for finding in findings:
            severity = finding.get("severity", "LOW")
            severity_counts[severity] += 1

        if severity_counts["CRITICAL"] > 0:
            recommendations.append("IMMEDIATE: Address all critical findings before mainnet deployment")
            recommendations.append("Consider full security audit by reputable firm")

        if severity_counts["HIGH"] > 0:
            recommendations.append("HIGH PRIORITY: Fix high-severity issues within 24-48 hours")
            recommendations.append("Implement additional access controls")

        if any(f["type"] == "ERC-2612 Permit Support" for f in findings):
            recommendations.append("Audit ERC-2612 permit implementation for unlimited approval vulnerabilities")
            recommendations.append("Implement permit amount limits and expiration checks")

        if any("reentrancy" in f["description"].lower() for f in findings):
            recommendations.append("Implement reentrancy guards (OpenZeppelin ReentrancyGuard)")
            recommendations.append("Use Checks-Effects-Interactions pattern")

        recommendations.extend([
            "Conduct comprehensive smart contract audit",
            "Implement multi-signature controls for critical functions",
            "Add comprehensive test coverage including edge cases",
            "Monitor contract activity for anomalous behavior"
        ])

        return recommendations

    def generate_security_report(self, scan_results: Dict[str, Any]) -> str:
        """Generate professional security report"""
        report = f"""
# DeFi Security Scan Report
**Protocol:** {scan_results['protocol']}
**Address:** {scan_results['address']}
**Scan Date:** {scan_results['scan_timestamp']}
**Overall Risk Score:** {scan_results['risk_score']}/100

## Executive Summary

{self._get_risk_assessment(scan_results['risk_score'])}

## Findings

"""

        for finding in scan_results['findings']:
            report += f"""
### {finding['severity']}: {finding['type']}
**Description:** {finding['description']}
**Risk Score:** {finding['risk_score']}
"""

        report += "\n## Recommendations\n\n"
        for rec in scan_results['recommendations']:
            report += f"- {rec}\n"

        report += "\n## Methodology\n\n"
        report += "This scan was performed using automated analysis techniques including:\n"
        report += "- Bytecode analysis for high-risk opcodes\n"
        report += "- ERC-20 permit vulnerability detection\n"
        report += "- Known malicious address database checks\n"
        report += "- Contract interface verification\n"

        return report

    def _get_risk_assessment(self, score: int) -> str:
        """Get risk assessment text based on score"""
        if score >= 80:
            return "CRITICAL RISK: Immediate security review required. Do not deploy to mainnet."
        elif score >= 60:
            return "HIGH RISK: Significant security concerns identified. Address before deployment."
        elif score >= 40:
            return "MEDIUM RISK: Moderate security issues found. Recommend fixes."
        elif score >= 20:
            return "LOW RISK: Minor issues identified. Good security posture overall."
        else:
            return "VERY LOW RISK: No significant security issues found."

# Commercial Service Interface
class DeFiSecurityService:
    """Monetizable DeFi security scanning service"""

    def __init__(self):
        self.scanner = DeFiSecurityScanner()
        self.client_database = {}  # Would be a real database in production
        self.logger = logging.getLogger("DeFiSecurityService")
        self.logger.setLevel(logging.INFO)
        handler = logging.StreamHandler()
        formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        handler.setFormatter(formatter)
        self.logger.addHandler(handler)
        self.pricing = {
            "basic_scan": 500,    # $500 for basic contract scan
            "full_audit": 2500,   # $2500 for comprehensive audit
            "monitoring": 1000    # $1000/month for ongoing monitoring
        }

    async def perform_paid_scan(self, client_id: str, protocol_address: str, protocol_name: str, scan_type: str = "basic") -> Dict[str, Any]:
        """Perform paid security scan service"""
        self.logger.info(f"Performing {scan_type} scan for client {client_id}: {protocol_name}")

        # Validate payment (would integrate with payment processor)
        if not self._validate_payment(client_id, scan_type):
            raise ValueError("Payment validation failed")

        # Perform scan
        results = await self.scanner.scan_protocol(protocol_address, protocol_name)

        # Generate professional report
        report = self.scanner.generate_security_report(results)

        # Store results for client
        self.client_database[client_id] = {
            "scan_results": results,
            "report": report,
            "scan_type": scan_type,
            "timestamp": datetime.now().isoformat()
        }

        return {
            "success": True,
            "report": report,
            "risk_score": results["risk_score"],
            "findings_count": len(results["findings"])
        }

    def _validate_payment(self, client_id: str, scan_type: str) -> bool:
        """Validate payment for service (mock implementation)"""
        # In real implementation, integrate with Stripe, PayPal, crypto payments, etc.
        expected_amount = self.pricing.get(scan_type, 0)
        self.logger.info(f"Validating payment for client {client_id}: ${expected_amount} for {scan_type} scan")
        # Mock validation - would check payment records
        return True

    def get_service_pricing(self) -> Dict[str, Any]:
        """Return service pricing information"""
        return {
            "services": self.pricing,
            "currency": "USD",
            "description": "Professional DeFi security scanning services",
            "features": [
                "Automated vulnerability detection",
                "ERC-20 permit analysis",
                "Known threat database checks",
                "Professional security reports",
                "Ongoing monitoring options"
            ]
        }

async def main():
    """Demo of the DeFi Security Scanner service"""
    service = DeFiSecurityService()

    print("DeFi Security Scanner - Commercial Service Demo")
    print("=" * 50)

    # Show pricing
    pricing = service.get_service_pricing()
    print(f"Service Pricing ({pricing['currency']}):")
    for service_type, price in pricing['services'].items():
        print(f"  {service_type}: ${price}")

    print(f"\nFeatures: {', '.join(pricing['features'])}")

    # Demo scan (would require real contract address)
    print("\nDemo: Scanning USDC contract for vulnerabilities...")
    try:
        # USDC contract address on Ethereum
        usdc_address = "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"
        results = await service.perform_paid_scan(
            client_id="demo_client",
            protocol_address=usdc_address,
            protocol_name="USD Coin (USDC)",
            scan_type="basic"
        )

        print(f"Scan completed successfully!")
        print(f"Risk Score: {results['risk_score']}/100")
        print(f"Findings: {results['findings_count']}")

        # Print first part of report
        report_lines = results['report'].split('\n')[:20]
        print("\nReport Preview:")
        print('\n'.join(report_lines))
        print("... (truncated)")

    except Exception as e:
        print(f"Demo scan failed: {e}")
        print("Note: This demo requires a valid Infura API key for Web3 connectivity")

if __name__ == "__main__":
    asyncio.run(main())