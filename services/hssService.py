#!/usr/bin/env python3
"""
HSS Service mit Zn-Interface Integration
Zeigt wie das Zn-Interface in den bestehenden PyHSS Service integriert wird
"""

import sys
import yaml
import os

# Bestehende PyHSS Imports
from diameter import Diameter
from database import Database
from logTool import LogTool
from messaging import RedisMessaging

# Neue Zn-Interface Imports
from zn_interface import initialize_zn_interface, ZnInterface, ZnDiameterExtension


def load_config():
    """Lädt die Konfiguration aus config.yaml"""
    with open('config.yaml', 'r') as file:
        config = yaml.safe_load(file)
    return config


def initialize_hss_service():
    """
    Initialisiert den HSS Service mit Zn-Interface Support
    """
    print("Initializing HSS Service with Zn-Interface support...")
    
    # Konfiguration laden
    config = load_config()
    
    # Logging initialisieren
    log_tool = LogTool(config)
    
    # Redis Messaging initialisieren
    redis_messaging = RedisMessaging(
        host=config.get('redis', {}).get('host', 'localhost'),
        port=config.get('redis', {}).get('port', 6379)
    )
    
    # Datenbank initialisieren
    database = Database(config)
    
    # Diameter Protokoll initialisieren
    diameter = Diameter(
        logTool=log_tool,
        redisMessaging=redis_messaging,
        database=database,
        config=config
    )
    
    log_tool.log(
        service='HSS',
        level='info',
        message="Base HSS services initialized",
        redisClient=redis_messaging
    )
    
    # Zn-Interface initialisieren (wenn aktiviert)
    zn_enabled = config.get('hss', {}).get('Zn_enabled', False)
    
    if zn_enabled:
        log_tool.log(
            service='HSS',
            level='info',
            message="Zn-Interface is enabled, initializing...",
            redisClient=redis_messaging
        )
        
        try:
            # Zn-Interface Extension registrieren
            zn_extension, zn_interface = initialize_zn_interface(diameter, config)
            
            log_tool.log(
                service='HSS',
                level='info',
                message="Zn-Interface successfully initialized and registered",
                redisClient=redis_messaging
            )
            
            # Zeige registrierte Zn Commands
            log_tool.log(
                service='HSS',
                level='info',
                message=f"Total Diameter commands registered: {len(diameter.diameterCommandList)}",
                redisClient=redis_messaging
            )
            
        except Exception as e:
            log_tool.log(
                service='HSS',
                level='error',
                message=f"Failed to initialize Zn-Interface: {str(e)}",
                redisClient=redis_messaging
            )
            raise
    else:
        log_tool.log(
            service='HSS',
            level='info',
            message="Zn-Interface is disabled in configuration",
            redisClient=redis_messaging
        )
    
    return diameter, database, log_tool, redis_messaging


def main():
    """
    Hauptfunktion - Startet den HSS Service
    """
    try:
        # Service initialisieren
        diameter, database, log_tool, redis_messaging = initialize_hss_service()
        
        print("HSS Service started successfully")
        print(f"Listening on {diameter.bind_ip}:{diameter.bind_port}")
        print(f"Origin-Host: {diameter.OriginHost}")
        print(f"Origin-Realm: {diameter.OriginRealm}")
        
        # Zeige ob Zn-Interface aktiv ist
        config = load_config()
        if config.get('hss', {}).get('Zn_enabled', False):
            print("✓ Zn-Interface (GBA) enabled")
            bsf_hostname = config.get('hss', {}).get('bsf', {}).get('bsf_hostname', 'N/A')
            print(f"  BSF Hostname: {bsf_hostname}")
        else:
            print("✗ Zn-Interface (GBA) disabled")
        
        # Zeige unterstützte Interfaces
        print("\nSupported Diameter Interfaces:")
        for cmd in diameter.diameterCommandList:
            if cmd.get('applicationId') == 16777220:  # Zh/Zn Application ID
                print(f"  - {cmd['requestAcronym']}/{cmd['responseAcronym']}: "
                      f"{cmd['requestName']} (Zn-Interface)")
        
        # HSS Service Loop würde hier weiterlaufen
        # (In der echten Implementation)
        
    except KeyboardInterrupt:
        print("\nShutting down HSS Service...")
        sys.exit(0)
    except Exception as e:
        print(f"Fatal error: {str(e)}")
        sys.exit(1)


if __name__ == "__main__":
    main()
