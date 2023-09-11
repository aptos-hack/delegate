import { Dispatch, SetStateAction, useEffect, useState } from "react";
import { Button, Menu, Modal, Typography } from "antd";
import {
  isRedirectable,
  useWallet,
  Wallet,
  WalletName,
  WalletReadyState,
} from "@aptos-labs/wallet-adapter-react";
const { Text } = Typography;

type WalletSelectorProps = {
  isModalOpen?: boolean;
  setModalOpen?: Dispatch<SetStateAction<boolean>>;
};

export const truncateAddress = (address: string | undefined) => {
  if (!address) return;
  return `${address.slice(0, 6)}...${address.slice(-5)}`;
};

export function WalletSelector({
                                 isModalOpen,
                                 setModalOpen,
                               }: WalletSelectorProps) {
  const [walletSelectorModalOpen, setWalletSelectorModalOpen] = useState(false);

  useEffect(() => {
    if (isModalOpen !== undefined) {
      setWalletSelectorModalOpen(isModalOpen);
    }
  }, [isModalOpen]);

  const { connect, disconnect, account, wallets, connected } = useWallet();

  const   onWalletButtonClick = () => {
    if (connected) {
      disconnect();
    } else {
      setWalletSelectorModalOpen(true);
    }
  };

  const onWalletSelected = (wallet: WalletName) => {
    connect(wallet);
    setWalletSelectorModalOpen(false);
    if (setModalOpen) {
      setModalOpen(false);
    }
  };
  const onCancel = () => {
    setWalletSelectorModalOpen(false);
    if (setModalOpen) {
      setModalOpen(false);
    }
  };
  const buttonText = account?.ansName
    ? account?.ansName
    : truncateAddress(account?.address);
  return (
    <>
      {/*<Button className="wallet-button" onClick={() => onWalletButtonClick()}>*/}
      {/*  {connected ? buttonText : "Connect Wallet"}*/}
      {/*</Button>*/}
      <button type="button"
              className="relative rounded-full bg-white p-1 text-gray-400 hover:text-gray-500 focus:outline-none focus:ring-2 focus:ring-indigo-500 focus:ring-offset-2"
              onClick={() => onWalletButtonClick()}
      >
        {connected ? buttonText : "Connect Wallet"}
      </button>
      <Modal
        title={<div className="wallet-modal-title">Connect Wallet</div>}
        centered
        open={walletSelectorModalOpen}
        onCancel={onCancel}
        footer={[]}
        closable={false}
        zIndex={9999}
      >
        {!connected && (
          <Menu>
            {wallets.map((wallet: Wallet) => {
              return walletView(wallet, onWalletSelected);
            })}
          </Menu>
        )}
      </Modal>
    </>
  );
}

const walletView = (
  wallet: Wallet,
  onWalletSelected: (wallet: WalletName) => void
) => {
  const isWalletReady =
    wallet.readyState === WalletReadyState.Installed ||
    wallet.readyState === WalletReadyState.Loadable;
  const mobileSupport = wallet.deeplinkProvider;

  if (!isWalletReady && isRedirectable()) {
    if (mobileSupport) {
      return (
        <Menu.Item
          key={wallet.name}
          onClick={() => onWalletSelected(wallet.name)}
        >
          <div className="wallet-menu-wrapper">
            <div className="wallet-name-wrapper">
              <img src={wallet.icon} width={25} style={{ marginRight: 10 }} />
              <Text className="wallet-selector-text">{wallet.name}</Text>
            </div>
            <Button className="wallet-connect-button">
              <Text className="wallet-connect-button-text">Connect</Text>
            </Button>
          </div>
        </Menu.Item>
      );
    } else {
      return (
        <Menu.Item key={wallet.name} disabled={true}>
          <div className="wallet-menu-wrapper">
            <div className="wallet-name-wrapper">
              <img src={wallet.icon} width={25} style={{ marginRight: 10 }} />
              <Text className="wallet-selector-text">{wallet.name}</Text>
            </div>
          </div>
        </Menu.Item>
      );
    }
  } else {
    return (
      <Menu.Item
        key={wallet.name}
        onClick={
          wallet.readyState === WalletReadyState.Installed ||
          wallet.readyState === WalletReadyState.Loadable
            ? () => onWalletSelected(wallet.name)
            : () => window.open(wallet.url)
        }
      >
        <div className="wallet-menu-wrapper">
          <div className="wallet-name-wrapper">
            <img src={wallet.icon} width={25} style={{ marginRight: 10 }} />
            <Text className="wallet-selector-text">{wallet.name}</Text>
          </div>
          {wallet.readyState === WalletReadyState.Installed ||
          wallet.readyState === WalletReadyState.Loadable ? (
            <Button className="wallet-connect-button">
              <Text className="wallet-connect-button-text">Connect</Text>
            </Button>
          ) : (
            <Text className="wallet-connect-install">Install</Text>
          )}
        </div>
      </Menu.Item>
    );
  }
};