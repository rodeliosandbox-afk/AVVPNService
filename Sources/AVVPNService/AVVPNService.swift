//
//  AVVPNService.swift
//  AVVPNService
//
//  Created by Andrey Vasilev on 17.04.2020.
//  Copyright © 2020 Andrey Vasilev. All rights reserved.
//

import Foundation
import NetworkExtension

public class AVVPNService {

    public static let shared = AVVPNService()
    public weak var delegate: AVVPNServiceDelegate?
    public let vpnManager = NEVPNManager.shared()

    private init() {
        NotificationCenter.default.addObserver(self, selector: #selector(didChangeStatus(_:)), name: NSNotification.Name.NEVPNStatusDidChange, object: nil)
    }

    //Set credentials = nil if you don't want to re-save protocolConfiguration
    public func connect(credentials: AVVPNCredentials? = nil, _ completion: @escaping (Error?) -> Void) {
        vpnManager.loadFromPreferences(completionHandler: loadHandler(credentials: credentials, toSave: true, completion))
    }

    public func disconnect() {
        // Отключаем on-demand, чтобы VPN не восстанавливался автоматически
        vpnManager.loadFromPreferences { [weak self] error in
            guard let self = self else { return }
            guard error == nil else {
                print("⚠️ Could not load VPN Configuration: \(error!.localizedDescription)")
                self.vpnManager.connection.stopVPNTunnel()
                return
            }
            self.vpnManager.isOnDemandEnabled = false
            self.vpnManager.saveToPreferences { _ in
                self.vpnManager.connection.stopVPNTunnel()
            }
        }
    }

    public func removeConfiguration( _ completion: ((Error?) -> Void)? = nil) {
        vpnManager.removeFromPreferences() {
            AVVPNUserDefaultsService.didRemovePreferences()
            if let error = $0 {
                print("⚠️ Could not remove VPN Configuration: \(error.localizedDescription)")
            }
            if let completion = completion {
                completion($0)
            }
        }
    }

    public func getStatus(_ completion: @escaping (NEVPNStatus?) -> Void) {
        if vpnManager.protocolConfiguration == nil {
            vpnManager.loadFromPreferences { _ in
                completion(self.vpnManager.connection.status)
            }
        } else {
            completion(vpnManager.connection.status)
        }
    }
}

// MARK: Protocol Configuration

private extension AVVPNService {
    func getProtocolConfiguration(_ credentials: AVVPNCredentials) -> NEVPNProtocol? {
        if credentials.type == .ipsec,
            let credentials = credentials as? AVVPNCredentials.IPSec {
            return getProtocolConfiguration(credentials)
        } else if credentials.type == .ike2,
            let credentials = credentials as? AVVPNCredentials.IKEv2 {
            return getProtocolConfiguration(credentials)
        } else {
            return nil
        }
    }

    func getProtocolConfiguration(_ credentials: AVVPNCredentials.IPSec) -> NEVPNProtocolIPSec {
        let configuration = NEVPNProtocolIPSec()
        configuration.username = credentials.username
        configuration.serverAddress = credentials.server
        configuration.authenticationMethod = NEVPNIKEAuthenticationMethod.sharedSecret
        let keychain = AVVPNKeychainService();
        keychain.save(key: AVVPNKeychainService.sharedKey, value: credentials.shared)
        keychain.save(key: AVVPNKeychainService.passwordKey, value: credentials.password)
        configuration.sharedSecretReference = keychain.load(key: AVVPNKeychainService.sharedKey)
        configuration.passwordReference = keychain.load(key: AVVPNKeychainService.passwordKey)
        configuration.useExtendedAuthentication = true
        configuration.disconnectOnSleep = false
        return configuration
    }

    func getProtocolConfiguration(_ credentials: AVVPNCredentials.IKEv2) -> NEVPNProtocolIKEv2 {
        let keychain = AVVPNKeychainService()
        keychain.save(key: AVVPNKeychainService.passwordKey, value: credentials.password)

        let ikev2 = NEVPNProtocolIKEv2()

        ikev2.serverAddress = credentials.server
        ikev2.remoteIdentifier = credentials.remoteId
        ikev2.localIdentifier = credentials.localId

        ikev2.authenticationMethod = .none
        ikev2.useExtendedAuthentication = true
        ikev2.username = credentials.username
        ikev2.passwordReference = keychain.load(key: AVVPNKeychainService.passwordKey)

        ikev2.ikeSecurityAssociationParameters.encryptionAlgorithm = .algorithmAES256GCM
        ikev2.ikeSecurityAssociationParameters.integrityAlgorithm = .SHA384
        ikev2.ikeSecurityAssociationParameters.diffieHellmanGroup = .group20
        ikev2.ikeSecurityAssociationParameters.lifetimeMinutes = 480

        ikev2.childSecurityAssociationParameters.encryptionAlgorithm = .algorithmAES256GCM
        ikev2.childSecurityAssociationParameters.integrityAlgorithm = .SHA384
        ikev2.childSecurityAssociationParameters.diffieHellmanGroup = .group20
        ikev2.childSecurityAssociationParameters.lifetimeMinutes = 60

        ikev2.deadPeerDetectionRate = .medium
        if #available(iOS 14.0, *) {
            ikev2.includeAllNetworks = true
        }
        if #available(iOS 14.2, *) {
            ikev2.excludeLocalNetworks = false
        }
        if #available(iOS 16.4, *) {
            ikev2.excludeAPNs = false
            ikev2.excludeCellularServices = false
        }
        ikev2.disconnectOnSleep = false
        ikev2.disableRedirect = true
        ikev2.enablePFS = true
        ikev2.disableMOBIKE = false
        ikev2.enableRevocationCheck = true

        return ikev2
    }
}

// MARK: Connection lifecycle

private extension AVVPNService {

    @objc func didChangeStatus(_ notification: Notification) {
        if let connection = notification.object as? NEVPNConnection {
            delegate?.vpnService(self, didChange: connection.status)
        }
    }

    func loadHandler(credentials: AVVPNCredentials?, toSave: Bool, _ completion: @escaping (Error?) -> Void) -> (Error?) -> Void {
        return { error in
            guard error == nil else {
                print("⚠️ Could not load VPN Configuration: \(error!.localizedDescription)")
                return completion(error)
            }
            if let credentials = credentials,
                toSave {
                self.vpnManager.isEnabled = true
                self.vpnManager.localizedDescription = credentials.title
                self.vpnManager.protocolConfiguration = self.delegate?.getProtocolConfiguration(credentials) ?? self.getProtocolConfiguration(credentials)
                
                // --- ВСТАВКА ОНДЕМАНД ---
                let rule = NEOnDemandRuleConnect()
                rule.interfaceTypeMatch = .any // подключение по любому типу интерфейса
                self.vpnManager.onDemandRules = [rule]
                self.vpnManager.isOnDemandEnabled = true
                // --- конец вставки ---
                
                self.vpnManager.saveToPreferences(completionHandler: self.saveHandler(credentials: credentials, completion))
            } else {
                //Add delay if protocolConfiguration was saved. Otherwise protocolConfiguration won't be reset
                let delay = toSave ? 0 : 0.3
                DispatchQueue.main.asyncAfter(deadline: .now() + delay) { [weak self] in
                    self?.startVPNTunnel(credentials: credentials, completion)
                }
            }
        }
    }

    func saveHandler(credentials: AVVPNCredentials, _ completion: @escaping (Error?) -> Void) -> (Error?) -> Void {
        return { error in
            guard error == nil else {
                print("⚠️ Could not save VPN Configuration: \(error!.localizedDescription)")
                return completion(error)
            }
            self.vpnManager.loadFromPreferences(completionHandler: self.loadHandler(credentials: credentials, toSave: false, completion))
        }
    }

    func startVPNTunnel(credentials: AVVPNCredentials?, _ completion: @escaping (Error?) -> Void) {
        guard vpnManager.protocolConfiguration != nil else {
            return completion(NEVPNError(.configurationInvalid))
        }
        do {
            try vpnManager.connection.startVPNTunnel()
            completion(nil)
        } catch let error {
            print("⚠️ Starting VPN Tunnel failed: \(error.localizedDescription)");
            if (error as? NEVPNError)?.code == NEVPNError.Code.configurationInvalid,
                !AVVPNUserDefaultsService.isPreferencesSaved {
                //For no known reason the process of saving/loading the VPN configurations fails. On the 2nd time it works
                connect(credentials: credentials, completion)
                AVVPNUserDefaultsService.didSavePreferences()
            } else {
                completion(error)
            }
        }
    }
}
