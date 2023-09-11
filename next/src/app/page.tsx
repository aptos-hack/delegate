'use client'
import {AptosWalletAdapterProvider} from "@aptos-labs/wallet-adapter-react";
import {PetraWallet} from "petra-plugin-wallet-adapter";
import React, {useState} from "react";
import {WalletSelector} from "./WalletSelector";
import {Disclosure} from '@headlessui/react'
import {BellIcon} from '@heroicons/react/24/outline'
import DelegatePage from "./DelegatePage";
import ProgressBar, {StepState} from "./ProgressBar";
import RegistrationPage from "./RegistrationPage";
import {ExclamationTriangleIcon} from "@heroicons/react/20/solid";
import {ToastContainer} from "react-toastify";

function classNames(...classes: string[]): string {
  return classes.filter(Boolean).join(' ')
}

export default function Home() {
  const [ wallet, setWallet ] = useState<PetraWallet>(new PetraWallet());
  const [ step, setStep ] = useState<StepState>('Register')
  return (
    <AptosWalletAdapterProvider plugins={[wallet]}
                                autoConnect={true}>
      <ToastContainer />
      <Disclosure as="nav" className="bg-white shadow">
        <>
          <div className="mx-auto max-w-7xl px-2 sm:px-6 lg:px-8">
            <div className="flex h-16 items-center justify-end">
              <div className="flex justify-end">
                <div className="hidden sm:ml-6 sm:block">
                  <div className="flex justify-end space-x-4">
                    <button
                      type="button"
                      className="relative rounded-full bg-white p-1 text-gray-400 hover:text-gray-500 focus:outline-none focus:ring-2 focus:ring-indigo-500 focus:ring-offset-2"
                    >
                      <span className="absolute -inset-1.5" />
                      <span className="sr-only">View notifications</span>
                      <BellIcon className="h-6 w-6" aria-hidden="true" />
                    </button>
                    <WalletSelector />
                  </div>
                </div>
              </div>
            </div>
          </div>
        </>
      </Disclosure>
      <div className="mx-auto max-w-7xl px-4 sm:px-6 lg:px-8">
        <div className="mx-auto max-w-3xl">
          {/* Content goes here */}
          <ProgressBar step={step} setStep={setStep} />
          { renderContentPage(step) }
        </div>
      </div>

    </AptosWalletAdapterProvider>
  )
}

function renderContentPage(step: StepState): JSX.Element {
  switch (step) {
    case 'Register':
      return <RegistrationPage />;
    case 'Delegate':
      return <DelegatePage />;
    default:
      throw new Error('Unimplemented');
  }
}