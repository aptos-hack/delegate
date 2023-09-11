import {Bars4Icon, ViewColumnsIcon,} from '@heroicons/react/24/outline'
import {useState} from "react";
import DelegateInputModal, {DelegateType} from "./DelegateInputModal";
import {ExclamationTriangleIcon} from "@heroicons/react/20/solid";
import {useWallet} from "@aptos-labs/wallet-adapter-react";

const items = [
  {
    title: 'Delegate a wallet',
    description: 'Delegate your entire wallet.',
    icon: Bars4Icon,
    background: 'bg-pink-500',
    delegateType: DelegateType.DELEGATE_WALLET,
  },
  {
    title: 'Delegate a NFT',
    description: 'Will only delegate a specific token on a specific contract.',
    icon: ViewColumnsIcon,
    background: 'bg-blue-500',
    delegateType: DelegateType.DELEGATE_NFT,
  },
]

function classNames(...classes: string[]): string {
  return classes.filter(Boolean).join(' ')
}

export default function DelegatePage() {
  const [ open, setOpen ] = useState(false);
  const { account } = useWallet();
  const [ delegate, setDelegate ] = useState<DelegateType>(DelegateType.DELEGATE_NFT);
  return (
    <>
      {!account && (
        <div className="border-l-4 border-yellow-400 bg-yellow-50 p-4 w-full justify-center">
          <div className="flex justify-center">
            <div className="flex-shrink-0">
              <ExclamationTriangleIcon className="h-5 w-5 text-yellow-400" aria-hidden="true" />
            </div>
            <div className="ml-3">
              <p className="text-sm text-yellow-700">
                Login with Petra Wallet.{' '}
                {/*<a href="#" className="font-medium text-yellow-700 underline hover:text-yellow-600">*/}
                {/*  Upgrade your account to add more credits.*/}
                {/*</a>*/}
              </p>
            </div>
          </div>
        </div>
      )}

      <div>
      <h2 className="flex justify-center text-lg font-semibold leading-6 text-gray-900 mt-6">Delegation</h2>
      <ul role="list" className="mt-6 grid grid-cols-1 gap-6 border-b border-t border-gray-200 py-6 sm:grid-cols-2">
        {items.map((item, itemIdx) => (
          <li key={itemIdx} className="flow-root">
            <div className="relative -m-2 flex items-center space-x-4 rounded-xl p-2 focus-within:ring-2 focus-within:ring-indigo-500 hover:bg-gray-50"
              onClick={() => {
                setOpen(true);
                setDelegate(item.delegateType);
              }}
            >
              <div
                className={classNames(
                  item.background,
                  'flex h-16 w-16 flex-shrink-0 items-center justify-center rounded-lg'
                )}
              >
                <item.icon className="h-6 w-6 text-white" aria-hidden="true" />
              </div>
              <div>
                <h3 className="text-sm font-medium text-gray-900">
                  <a href="#" className="focus:outline-none">
                    <span className="absolute inset-0" aria-hidden="true" />
                    <span>{item.title}</span>
                    <span aria-hidden="true"> &rarr;</span>
                  </a>
                </h3>
                <p className="mt-1 text-sm text-gray-500">{item.description}</p>
              </div>
            </div>
          </li>
        ))}
      </ul>
    </div>
    {open && <DelegateInputModal setOpen={setOpen} open={open} delegateType={delegate} />}
    </>
  )
}
