import React from 'react';
import {Box, Text} from 'ink';
import {AppProvider, useApp, Screen} from './state/AppContext.js';
import {useTerminalSize} from './state/useTerminalSize.js';
import {LocaleProvider} from './i18n/LocaleProvider.js';
import {MouseProvider} from './input/mouseRegions.js';
import {ToastBar} from './components/Toast.js';
import {ContextsScreen} from './screens/ContextsScreen.js';
import {UnlockScreen} from './screens/UnlockScreen.js';
import {MainMenuScreen} from './screens/MainMenuScreen.js';
import {CertificatesScreen} from './screens/CertificatesScreen.js';
import {CertDetailsScreen} from './screens/CertDetailsScreen.js';
import {ReassignIssuerScreen} from './screens/ReassignIssuerScreen.js';
import {CreateCAScreen} from './screens/CreateCAScreen.js';
import {IssueCertScreen} from './screens/IssueCertScreen.js';
import {IssueIntermediateCAScreen} from './screens/IssueIntermediateCAScreen.js';
import {ProfilesScreen} from './screens/ProfilesScreen.js';
import {CreateProfileScreen} from './screens/CreateProfileScreen.js';
import {VerifyScreen} from './screens/VerifyScreen.js';
import {SniSearchScreen} from './screens/SniSearchScreen.js';
import {ExportContextScreen} from './screens/ExportContextScreen.js';
import {ImportContextScreen} from './screens/ImportContextScreen.js';
import {ImportCertScreen} from './screens/ImportCertScreen.js';
import {ImportProfileScreen} from './screens/ImportProfileScreen.js';
import {ExportCertScreen, ExportProfileScreen} from './screens/ExportCertScreen.js';
import {SetPasswordScreen} from './screens/SetPasswordScreen.js';
import {SettingsScreen} from './screens/SettingsScreen.js';
import {AuditScreen} from './screens/AuditScreen.js';
import {RenewCertScreen} from './screens/RenewCertScreen.js';
import {SignFileScreen} from './screens/SignFileScreen.js';
import {VerifySignatureScreen} from './screens/VerifySignatureScreen.js';
import {SshKeysScreen} from './screens/SshKeysScreen.js';
import {CreateSshKeyScreen} from './screens/CreateSshKeyScreen.js';
import {SshKeyDetailsScreen} from './screens/SshKeyDetailsScreen.js';

function Router() {
	const {current} = useApp();
	const screen: Screen = current;

	switch (screen.kind) {
		case 'contexts':         return <ContextsScreen />;
		case 'unlock':           return <UnlockScreen name={screen.name} />;
		case 'set-password':     return <SetPasswordScreen name={screen.name} />;
		case 'main':             return <MainMenuScreen />;
		case 'certificates':     return <CertificatesScreen filter={screen.filter} />;
		case 'cert-details':     return <CertDetailsScreen id={screen.id} />;
		case 'reassign-issuer':  return <ReassignIssuerScreen id={screen.id} />;
		case 'renew-cert':       return <RenewCertScreen id={screen.id} />;
		case 'create-ca':        return <CreateCAScreen />;
		case 'issue-intermediate-ca': return <IssueIntermediateCAScreen />;
		case 'issue-cert':       return <IssueCertScreen certType={screen.certType} />;
		case 'profiles':         return <ProfilesScreen />;
		case 'create-profile':   return <CreateProfileScreen certId={screen.certId} />;
		case 'verify':           return <VerifyScreen />;
		case 'sni-search':       return <SniSearchScreen />;
		case 'export-context':   return <ExportContextScreen />;
		case 'import-context':   return <ImportContextScreen />;
		case 'import-cert':      return <ImportCertScreen />;
		case 'import-profile':   return <ImportProfileScreen />;
		case 'export-cert':      return <ExportCertScreen id={screen.id} />;
		case 'export-profile':   return <ExportProfileScreen id={screen.id} />;
		case 'audit':            return <AuditScreen />;
		case 'sign-file':        return <SignFileScreen />;
		case 'verify-signature': return <VerifySignatureScreen />;
		case 'ssh-keys':         return <SshKeysScreen />;
		case 'create-ssh-key':   return <CreateSshKeyScreen />;
		case 'ssh-key-details':  return <SshKeyDetailsScreen id={screen.id} />;
		case 'settings':         return <SettingsScreen />;
		default:
			return (
				<Box>
					<Text color="red">Unknown screen</Text>
				</Box>
			);
	}
}

function Shell() {
	const {rows, columns} = useTerminalSize();
	return (
		<Box flexDirection="column" width={columns} height={rows}>
			<Box flexDirection="column" flexGrow={1}>
				<Router />
			</Box>
			<ToastBar />
		</Box>
	);
}

export function App({onExit}: {onExit: () => void}) {
	return (
		<LocaleProvider>
			<AppProvider initialScreen={{kind: 'contexts'}} onExit={onExit}>
				<MouseProvider>
					<Shell />
				</MouseProvider>
			</AppProvider>
		</LocaleProvider>
	);
}
