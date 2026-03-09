#!/usr/bin/env python3
"""
Network Protocol Analysis - Simulate deep network protocol RE
Predicts packet structures and handler patterns
"""

import json
from pathlib import Path
from collections import defaultdict

REPORTS_DIR = Path("./reports")

# Known WoW 3.3.5a packet structures (from public sources)
PACKET_STRUCTURES = {
    0x01ED: {  # CMSG_AUTH_SESSION
        'name': 'CMSG_AUTH_SESSION',
        'direction': 'C->S',
        'frequency': 'ONCE_PER_LOGIN',
        'fields': [
            ('uint16_t', 'opcode', '0x01ED'),
            ('uint32_t', 'build', '12340 for 3.3.5a'),
            ('uint32_t', 'account', 'Account ID'),
            ('uint32_t', 'unk1', 'Unknown'),
            ('uint32_t', 'client_seed', 'Random seed'),
            ('uint8[20]', 'digest', 'SHA1(account + auth_seed + client_seed + session_key)'),
            ('uint8[20]', 'unknown', 'Additional auth data'),
        ],
        'response_opcodes': [0x01EE],  # SMSG_AUTH_RESPONSE
    },
    
    0x00B5: {  # MSG_MOVE_START_FORWARD
        'name': 'MSG_MOVE_START_FORWARD',
        'direction': 'C<->S',
        'frequency': 'VERY_FREQUENT (multiple per second)',
        'fields': [
            ('uint16_t', 'opcode', '0x00B5'),
            ('uint32_t', 'flags', 'Movement flags'),
            ('uint32_t', 'tick', 'Server tick counter'),
            ('float', 'x', 'X position'),
            ('float', 'y', 'Y position'),
            ('float', 'z', 'Z position'),
            ('float', 'facing', 'Facing angle (radians)'),
        ],
        'handler_pattern': 'UpdatePlayerPosition',
        'network_impact': 'EXTREME (bandwidth heavy)',
    },
    
    0x00A9: {  # SMSG_UPDATE_OBJECT
        'name': 'SMSG_UPDATE_OBJECT',
        'direction': 'S->C',
        'frequency': 'VERY_FREQUENT (multiple per second)',
        'fields': [
            ('uint16_t', 'opcode', '0x00A9'),
            ('uint32_t', 'object_count', 'How many objects to update'),
            ('uint8[var]', 'movement_blocks', 'Movement data for each object'),
            ('uint8[var]', 'create_blocks', 'Creation data for new objects'),
            ('uint8[var]', 'out_of_range', 'Objects to destroy'),
        ],
        'handler_pattern': 'ProcessObjectUpdates',
        'network_impact': 'EXTREME (defines all object positions)',
        'note': 'Compressed version exists at 0x01F6'
    },
    
    0x012E: {  # CMSG_CAST_SPELL
        'name': 'CMSG_CAST_SPELL',
        'direction': 'C->S',
        'frequency': 'FREQUENT (when casting spells)',
        'fields': [
            ('uint16_t', 'opcode', '0x012E'),
            ('uint32_t', 'spell_id', 'Spell ID to cast'),
            ('uint8', 'cast_count', 'Cast counter'),
            ('uint32_t', 'target_guid', 'Target GUID (0 = self)'),
            ('uint8[var]', 'target_flags', 'Target flag bits'),
        ],
        'handler_pattern': 'ValidateAndCastSpell',
        'validation': ['CheckSpellLearned', 'CheckResources', 'CheckTarget', 'CheckRange'],
    },
    
    0x01EC: {  # CMSG_AUTH_CHALLENGE
        'name': 'CMSG_AUTH_CHALLENGE',
        'direction': 'S->C during handshake',
        'frequency': 'ONCE_PER_LOGIN',
        'fields': [
            ('uint16_t', 'opcode', '0x01EC'),
            ('uint32_t', 'server_seed', 'Random seed from server'),
            ('uint8[32]', 'proof', 'SRP6 proof or challenge'),
        ],
        'precedes': 0x01ED,
    },
}

def analyze_packet_flow():
    """Analyze expected packet flow"""
    
    flow = {
        'initialization': [
            {
                'step': 1,
                'opcode': 0x01EC,
                'name': 'CMSG_AUTH_CHALLENGE',
                'direction': 'S->C',
                'purpose': 'Server sends challenge'
            },
            {
                'step': 2,
                'opcode': 0x01ED,
                'name': 'CMSG_AUTH_SESSION',
                'direction': 'C->S',
                'purpose': 'Client sends authentication'
            },
            {
                'step': 3,
                'opcode': 0x01EE,
                'name': 'SMSG_AUTH_RESPONSE',
                'direction': 'S->C',
                'purpose': 'Server accepts/rejects auth'
            },
        ],
        
        'runtime': [
            {
                'opcode_range': '0x00B5-0x00EE',
                'category': 'Movement opcodes',
                'frequency': 'EXTREME (continuous)',
                'purpose': 'Player movement synchronization'
            },
            {
                'opcode': 0x00A9,
                'category': 'SMSG_UPDATE_OBJECT',
                'frequency': 'EXTREME (continuous)',
                'purpose': 'World object updates (position, health, etc.)'
            },
            {
                'opcode': 0x012E,
                'category': 'CMSG_CAST_SPELL',
                'frequency': 'FREQUENT (when spellcasting)',
                'purpose': 'Spell cast requests'
            },
            {
                'opcode_range': '0x0095-0x0096',
                'category': 'Chat opcodes',
                'frequency': 'NORMAL',
                'purpose': 'Chat messages'
            },
        ]
    }
    
    return flow

def predict_handler_structure(opcode_name, opcode_value):
    """Predict handler function structure"""
    
    handler = {
        'opcode': opcode_name,
        'value': f'0x{opcode_value:04X}',
        'predicted_handler_pattern': f'Handle{opcode_name.replace("_", "")}',
        'expected_operations': [],
        'expected_reads': []
    }
    
    if 'AUTH' in opcode_name:
        handler['expected_operations'].extend([
            'Read packet data',
            'Validate build number (12340)',
            'Decrypt session key',
            'Verify SHA1 digest',
            'Load character list',
            'Send auth response'
        ])
        handler['expected_reads'] = [
            'uint32 build',
            'uint32 account_id',
            'uint8[20] digest',
        ]
    
    elif 'MOVE' in opcode_name or 'HEARTBEAT' in opcode_name:
        handler['expected_operations'].extend([
            'Read movement data',
            'Update player position',
            'Check collision',
            'Broadcast to nearby players',
            'Update world state'
        ])
        handler['expected_reads'] = [
            'float position_x', 'float position_y', 'float position_z',
            'float facing_angle',
            'uint32 movement_flags'
        ]
    
    elif 'UPDATE_OBJECT' in opcode_name:
        handler['expected_operations'].extend([
            'Read object count',
            'Process movement blocks',
            'Process creation blocks',
            'Process destruction blocks',
            'Update local entity cache',
        ])
        handler['expected_reads'] = [
            'uint32 object_count',
            'variable-length update blocks'
        ]
    
    elif 'CAST' in opcode_name and 'SPELL' in opcode_name:
        handler['expected_operations'].extend([
            'Read spell ID',
            'Read target GUID',
            'Validate spell learned',
            'Check mana/resources',
            'Check spell range',
            'Validate target type',
            'Send spell start/go',
        ])
        handler['expected_reads'] = [
            'uint32 spell_id',
            'uint32 target_guid',
            'uint8 cast_count'
        ]
    
    return handler

def generate_network_analysis():
    """Generate comprehensive network protocol analysis"""
    
    print("[*] Analyzing WoW 3.3.5a network protocol...")
    
    # Load cached data
    with open(REPORTS_DIR / "CRITICAL_FUNCTIONS.json", 'r') as f:
        critical = json.load(f)
    
    packet_flow = analyze_packet_flow()
    
    analysis = {
        'protocol': 'World of Warcraft 3.3.5a (TrinityCore)',
        'transport': 'TCP over WinSocket (async IOCP)',
        'packet_format': {
            'header': [
                ('uint16_t', 'opcode', 'Packet type identifier'),
                ('uint16_t', 'size', 'Remaining data size (optional)'),
            ],
            'payload': 'Variable length, specific to opcode'
        },
        'known_packets': {},
        'packet_flow': packet_flow,
        'handler_predictions': {}
    }
    
    # Add packet structures
    for opcode, pkt_info in PACKET_STRUCTURES.items():
        analysis['known_packets'][f'0x{opcode:04X}'] = pkt_info
        
        # Predict handler
        handler = predict_handler_structure(pkt_info['name'], opcode)
        analysis['handler_predictions'][f'0x{opcode:04X}'] = handler
    
    # Key statistics
    analysis['statistics'] = {
        'known_opcode_structures': len(PACKET_STRUCTURES),
        'estimated_total_opcodes': '100-300',
        'critical_packets': {
            'auth': 3,
            'movement': 10,
            'object_updates': 5,
            'spells': 10,
            'chat': 4,
        }
    }
    
    # Save analysis
    output_path = REPORTS_DIR / "NETWORK_PROTOCOL_ANALYSIS.json"
    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump(analysis, f, indent=2)
    print(f"[+] JSON analysis saved to: {output_path}")
    
    # Generate markdown
    md = "# WoW 3.3.5a Network Protocol Analysis\n\n"
    md += "**Protocol:** World of Warcraft build 12340 (Patch 3.3.5a)\n"
    md += "**Transport:** TCP with async IOCP (Windows I/O Completion Ports)\n"
    md += "**Known Opcodes Documented:** {}\n\n".format(len(PACKET_STRUCTURES))
    
    md += "## Authentication Flow\n\n"
    for step in packet_flow['initialization']:
        md += f"### Step {step['step']}: {step['name']} (0x{step['opcode']:04X})\n\n"
        md += f"- **Direction:** {step['direction']}\n"
        md += f"- **Purpose:** {step['purpose']}\n\n"
    
    md += "## Runtime Packet Patterns\n\n"
    for pattern in packet_flow['runtime']:
        if 'opcode_range' in pattern:
            md += f"### {pattern['category']}\n"
        else:
            md += f"### {pattern['opcode']:04X} - {pattern['category']}\n"
        
        md += f"- **Frequency:** {pattern['frequency']}\n"
        md += f"- **Purpose:** {pattern['purpose']}\n\n"
    
    md += "## Known Packet Structures\n\n"
    for opcode_hex, pkt_info in sorted(analysis['known_packets'].items()):
        md += f"### {opcode_hex} - {pkt_info['name']}\n\n"
        md += f"**Direction:** {pkt_info['direction']}\n"
        md += f"**Frequency:** {pkt_info.get('frequency', 'UNKNOWN')}\n\n"
        
        if pkt_info['fields']:
            md += "**Fields:**\n\n"
            md += "| Type | Name | Description |\n"
            md += "|------|------|-------------|\n"
            for field_type, field_name, field_desc in pkt_info['fields']:
                md += f"| `{field_type}` | {field_name} | {field_desc} |\n"
            md += "\n"
        
        if 'handler_pattern' in pkt_info:
            md += f"**Expected Handler:** `{pkt_info['handler_pattern']}`\n\n"
        
        if 'validation' in pkt_info:
            md += "**Validation Checks:**\n"
            for check in pkt_info['validation']:
                md += f"- {check}\n"
            md += "\n"
    
    md += "## Handler Prediction Patterns\n\n"
    md += "Predicted handler operations by opcode:\n\n"
    for opcode_hex, handler in sorted(analysis['handler_predictions'].items()):
        md += f"### {opcode_hex} Handler\n\n"
        md += "**Expected Operations:**\n"
        for op in handler['expected_operations']:
            md += f"- {op}\n"
        md += "\n"
    
    md += "## Live Analysis Commands\n\n"
    md += "When MCP available, find handlers with:\n\n"
    md += "```python\n"
    md += "# Find network I/O handler (entry point for all packets)\n"
    md += 'xrefs(address=\"CreateIoCompletionPort\", direction=\"to\")\n'
    md += 'xrefs(address=\"GetOverlappedResult\", direction=\"to\")\n\n'
    
    md += "# Find opcode dispatcher\n"
    md += "search_bytes(pattern=\"ed 01\")  # 0x01ED CMSG_AUTH_SESSION\n"
    md += "search_bytes(pattern=\"b5 00\")  # 0x00B5 MSG_MOVE_START_FORWARD\n"
    md += "search_bytes(pattern=\"a9 00\")  # 0x00A9 SMSG_UPDATE_OBJECT\n\n"
    
    md += "# Decompile dispatcher\n"
    md += "get_code(address=\"<dispatcher_addr>\", mode=\"decompiled\")\n"
    md += "get_basic_blocks(address=\"<dispatcher_addr>\")  # Count switch cases\n"
    md += "```\n"
    
    md_path = REPORTS_DIR / "NETWORK_PROTOCOL_ANALYSIS.md"
    with open(md_path, 'w', encoding='utf-8') as f:
        f.write(md)
    print(f"[+] Markdown analysis saved to: {md_path}")
    
    return analysis

def main():
    print("=" * 80)
    print("WoW 3.3.5a NETWORK PROTOCOL ANALYZER")
    print("=" * 80)
    print()
    
    try:
        analysis = generate_network_analysis()
        
        print("\n" + "=" * 80)
        print("PROTOCOL ANALYSIS COMPLETE")
        print("=" * 80)
        print(f"\nKnownPackets Documented: {analysis['statistics']['known_opcode_structures']}")
        print(f"Estimated Total Opcodes: {analysis['statistics']['estimated_total_opcodes']}")
        print(f"Critical Opcode Categories:")
        for cat, count in analysis['statistics']['critical_packets'].items():
            print(f"  {cat:20s}: {count:3d} opcodes")
        
        print("\n" + "=" * 80)
        
    except Exception as e:
        print(f"[!] Error: {e}")
        import traceback
        traceback.print_exc()
        return 1
    
    return 0

if __name__ == "__main__":
    exit(main())
