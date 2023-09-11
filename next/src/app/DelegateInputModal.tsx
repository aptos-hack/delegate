import {Dispatch, Fragment, useState} from 'react'
import {Dialog, Transition} from '@headlessui/react'
import {useWallet} from "@aptos-labs/wallet-adapter-react";
import env from './env.json'
import {Types} from "aptos";
import {toast} from "react-toastify";

export enum DelegateType {
  DELEGATE_NFT = 'DELEGATE_NFT',
  DELEGATE_CONTRACT = 'DELEGATE_CONTRACT',
  DELEGATE_WALLET = 'DELEGATE_WALLET',
}

export default function DelegateInputModal(props: { open: boolean; setOpen: Dispatch<boolean>, delegateType: DelegateType; } ) {
  const { open, setOpen, delegateType } = props;
  const [delegateAddress, setDelegateAddress] = useState('');
  const [contractAddress, setContractAddress] = useState('');
  const [tokenId, setTokenId] = useState('');

  const { account, signAndSubmitTransaction } = useWallet();

  async function callSendTx(delegateAddress: string): Promise<void> {
    if (!account) throw new Error('account cannot be null');
    let payload: Types.TransactionPayload = {
      type: 'entry_function_payload',
      function: `${env.devnet.contractAddress}::delegate::delegate_for_all`,
      type_arguments: [],
      arguments: [delegateAddress, true]
    }
    try {
      const tx = await signAndSubmitTransaction(payload);
      toast.success(
        `Delegated successfully
          Transaction hash - ${tx.hash}
        `);
    } catch (err) {
      console.log(err);
      toast.error('Failed to delegate');
    }
  }
  return (
    <>
      <Transition.Root show={open} as={Fragment}>
        <Dialog as="div"
                className="relative z-10"
                onClose={setOpen}
        >
          <Transition.Child
            as={Fragment}
            enter="ease-out duration-300"
            enterFrom="opacity-0"
            enterTo="opacity-100"
            leave="ease-in duration-200"
            leaveFrom="opacity-100"
            leaveTo="opacity-0"
          >
            <div className="fixed inset-0 bg-gray-500 bg-opacity-75 transition-opacity" />
          </Transition.Child>

          <div className="fixed inset-0 z-10 overflow-y-auto">
            <div className="flex min-h-full items-end justify-center p-4 text-center sm:items-center sm:p-0">
              <Transition.Child
                as={Fragment}
                enter="ease-out duration-300"
                enterFrom="opacity-0 translate-y-4 sm:translate-y-0 sm:scale-95"
                enterTo="opacity-100 translate-y-0 sm:scale-100"
                leave="ease-in duration-200"
                leaveFrom="opacity-100 translate-y-0 sm:scale-100"
                leaveTo="opacity-0 translate-y-4 sm:translate-y-0 sm:scale-95"
              >
                {
                  renderDelegateForm(
                    delegateType,
                    setOpen,
                    {setDelegateAddress, delegateAddress,},
                    {setContractAddress, contractAddress,},
                    {setTokenId, tokenId},
                    callSendTx,
                  )
                }
              </Transition.Child>
            </div>
          </div>
        </Dialog>
      </Transition.Root>
    </>
  )
}

function renderDelegateForm(
  delegateType: DelegateType,
  setOpen: Dispatch<boolean>,
  handleDelegateAddress: { setDelegateAddress: Dispatch<string>; delegateAddress: string; },
  handleContractAddress: { setContractAddress: Dispatch<string>; contractAddress: string },
  handleTokenId: { setTokenId: Dispatch<string>; tokenId: string },
  callTx: (delegateAddress: string) => void,
): JSX.Element {
  switch (delegateType) {
    case 'DELEGATE_NFT':
      return renderDelegateNft(setOpen, handleDelegateAddress, handleContractAddress, handleTokenId);
    case 'DELEGATE_CONTRACT':
      return renderDelegateContract(setOpen, handleDelegateAddress, handleContractAddress);
    case 'DELEGATE_WALLET':
      return renderDelegateWallet(setOpen, handleDelegateAddress, callTx);
    default:
      throw new Error('Unsupported');
  }
}

function renderDelegateWallet(
  setOpen: Dispatch<boolean>,
  handleDelegateAddress: { setDelegateAddress: Dispatch<string>; delegateAddress: string; },
  callTx: (delegateAddress: string) => void,
): JSX.Element {
  const { setDelegateAddress, delegateAddress } = handleDelegateAddress;
  return (
    <Dialog.Panel className="relative transform overflow-hidden rounded-lg bg-white px-12 pb-4 pt-5 text-left shadow-xl transition-all sm:my-8 sm:w-full sm:max-w-sm sm:p-6">
      <div>
        <div>
          <label htmlFor="delegate" className="block text-sm font-medium leading-6 text-gray-900 pb-4">
            Delegate Wallet
          </label>
          <div className="isolate -space-y-px rounded-md shadow-sm">
            <div className="relative rounded-md rounded-b-none px-3 pb-1.5 pt-2.5 ring-1 ring-inset ring-gray-300 focus-within:z-10 focus-within:ring-2 focus-within:ring-indigo-600">
              <label htmlFor="name" className="block text-xs font-medium text-gray-900">
                Delegate Address
              </label>
              <input
                type="text"
                name="delegate-address"
                id="delegate-address"
                onChange={(e) => setDelegateAddress(e.target.value)}
                className="block w-full border-0 p-0 text-gray-900 placeholder:text-gray-400 focus:ring-0 sm:text-sm sm:leading-6"
                placeholder="Example: Delegate your hot wallet - 0x00...000"
              />
            </div>
          </div>
        </div>
      </div>
      <div className="mt-5 sm:mt-6">
        <button
          type="button"
          className="inline-flex w-full justify-center rounded-md bg-indigo-600 px-3 py-2 text-sm font-semibold text-white shadow-sm hover:bg-indigo-500 focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-indigo-600"
          onClick={async () => {
            setOpen(false);
            await callTx(delegateAddress);
          }}
        >
          Delegate
        </button>
      </div>
    </Dialog.Panel>
  )
}

function renderDelegateContract(
  setOpen: Dispatch<boolean>,
  handleDelegateAddress: { setDelegateAddress: Dispatch<string>; delegateAddress: string; },
  handleContractAddress: { setContractAddress: Dispatch<string>; contractAddress: string },
): JSX.Element {
  const { delegateAddress, setDelegateAddress } = handleDelegateAddress;
  const { contractAddress, setContractAddress } = handleContractAddress;

  return (
    <Dialog.Panel className="relative transform overflow-hidden rounded-lg bg-white px-12 pb-4 pt-5 text-left shadow-xl transition-all sm:my-8 sm:w-full sm:max-w-sm sm:p-6">
      <div>
        <div>
          <label htmlFor="delegate" className="block text-sm font-medium leading-6 text-gray-900 pb-4">
            Delegate Contract
          </label>
          <div className="isolate -space-y-px rounded-md shadow-sm">
            <div className="relative rounded-md rounded-b-none px-3 pb-1.5 pt-2.5 ring-1 ring-inset ring-gray-300 focus-within:z-10 focus-within:ring-2 focus-within:ring-indigo-600">
              <label htmlFor="name" className="block text-xs font-medium text-gray-900">
                Delegate Address
              </label>
              <input
                type="text"
                name="delegate-address"
                id="delegate-address"
                onChange={(e) => setDelegateAddress(e.target.value)}
                className="block w-full border-0 p-0 text-gray-900 placeholder:text-gray-400 focus:ring-0 sm:text-sm sm:leading-6"
                placeholder="Example: Delegate your hot wallet - 0x00...000"
              />
            </div>
            <div className="relative rounded-md rounded-t-none px-3 pb-1.5 pt-2.5 ring-1 ring-inset ring-gray-300 focus-within:z-10 focus-within:ring-2 focus-within:ring-indigo-600">
              <label htmlFor="job-title" className="block text-xs font-medium text-gray-900">
                Contract Address
              </label>
              <input
                type="text"
                name="contract-address"
                onChange={(e) => setContractAddress(e.target.value)}
                id="contract-address"
                className="block w-full border-0 p-0 text-gray-900 placeholder:text-gray-400 focus:ring-0 sm:text-sm sm:leading-6"
                placeholder="Example: Address of NFT project - 0x00...000"
              />
            </div>
          </div>
        </div>
      </div>
      <div className="mt-5 sm:mt-6">
        <button
          type="button"
          className="inline-flex w-full justify-center rounded-md bg-indigo-600 px-3 py-2 text-sm font-semibold text-white shadow-sm hover:bg-indigo-500 focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-indigo-600"
          onClick={() => setOpen(false)}
        >
          Delegate
        </button>
      </div>
    </Dialog.Panel>
  )
}

function renderDelegateNft(
  setOpen: Dispatch<boolean>,
  handleDelegateAddress: { setDelegateAddress: Dispatch<string>; delegateAddress: string; },
  handleContractAddress: { setContractAddress: Dispatch<string>; contractAddress: string },
  handleTokenId: { setTokenId: Dispatch<string>; tokenId: string },
): JSX.Element {
  const { setDelegateAddress, delegateAddress } = handleDelegateAddress;
  const { setContractAddress, contractAddress } = handleContractAddress;
  const { setTokenId, tokenId } = handleTokenId;

  return (
    <Dialog.Panel className="relative transform overflow-hidden rounded-lg bg-white px-12 pb-4 pt-5 text-left shadow-xl transition-all sm:my-8 sm:w-full sm:max-w-sm sm:p-6">
      <div>
        <div>
          <label htmlFor="delegate" className="block text-sm font-medium leading-6 text-gray-900 pb-4">
            Delegate NFT
          </label>
          <div className="isolate -space-y-px rounded-md shadow-sm">
            <div className="relative rounded-md rounded-b-none px-3 pb-1.5 pt-2.5 ring-1 ring-inset ring-gray-300 focus-within:z-10 focus-within:ring-2 focus-within:ring-indigo-600">
              <label htmlFor="name" className="block text-xs font-medium text-gray-900">
                Delegate Address
              </label>
              <input
                type="text"
                name="delegate-address"
                id="delegate-address"
                onChange={(e) => setDelegateAddress(e.target.value)}
                className="block w-full border-0 p-0 text-gray-900 placeholder:text-gray-400 focus:ring-0 sm:text-sm sm:leading-6"
                placeholder="Example: Delegate your hot wallet - 0x00...000"
              />
            </div>
            <div className="relative rounded-md rounded-b-none rounded-t-none px-3 pb-1.5 pt-2.5 ring-1 ring-inset ring-gray-300 focus-within:z-10 focus-within:ring-2 focus-within:ring-indigo-600">
              <label htmlFor="job-title" className="block text-xs font-medium text-gray-900">
                Contract Address
              </label>
              <input
                type="text"
                name="contract-address"
                id="contract-address"
                onChange={(e) => setContractAddress(e.target.value)}
                className="block w-full border-0 p-0 text-gray-900 placeholder:text-gray-400 focus:ring-0 sm:text-sm sm:leading-6"
                placeholder="Example: Address of NFT project - 0x00...000"
              />
            </div>
            <div className="relative rounded-md rounded-t-none px-3 pb-1.5 pt-2.5 ring-1 ring-inset ring-gray-300 focus-within:z-10 focus-within:ring-2 focus-within:ring-indigo-600">
              <label htmlFor="job-title" className="block text-xs font-medium text-gray-900">
                Token ID
              </label>
              <input
                type="text"
                name="token-id"
                id="token-id"
                onChange={(e) => setTokenId(e.target.value)}
                className="block w-full border-0 p-0 text-gray-900 placeholder:text-gray-400 focus:ring-0 sm:text-sm sm:leading-6"
                placeholder="#"
              />
            </div>
          </div>
        </div>
      </div>
      <div className="mt-5 sm:mt-6">
        <button
          type="button"
          className="inline-flex w-full justify-center rounded-md bg-indigo-600 px-3 py-2 text-sm font-semibold text-white shadow-sm hover:bg-indigo-500 focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-indigo-600"
          onClick={() => setOpen(false)}
        >
          Delegate
        </button>
      </div>
    </Dialog.Panel>
  )
}
