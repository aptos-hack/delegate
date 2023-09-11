import {useWallet} from "@aptos-labs/wallet-adapter-react";
import {AptosClient, Types } from "aptos";
import env from "./env.json";
import {useEffect, useState} from "react";
import { ExclamationTriangleIcon } from '@heroicons/react/20/solid'
import 'react-toastify/dist/ReactToastify.css';
import {toast} from "react-toastify";

type RegistrationDetailType = {
  id: number;
  name: RegistryName;
  current?: boolean | undefined;
}

enum RegistryName {
  VAULT = 'Vault',
  DELEGATE = 'Delegate',
}

export default function RegistrationPage() {
  const client = new AptosClient(env.devnet.rpcUrl);
  const { account, isLoading, signAndSubmitTransaction } = useWallet();
  const [ toSubmitDelegate, submitDelegate ] = useState(false);
  const [ toSubmitVault, submitVault ] = useState(false);

  const [ registrationDetail, setRegistrationDetail ] = useState<RegistrationDetailType[]>([]);

  useEffect(() => {
    getState().then((a) => {
      if (a) {
        setRegistrationDetail([
          { id: 1, name: RegistryName.VAULT, current: a.currentVault },
          { id: 2, name: RegistryName.DELEGATE, current: a.currentDelegate },
        ]);
      }
    })
  }, [isLoading, account])

  const getState = async () : Promise<{ currentVault: boolean | undefined; currentDelegate: boolean | undefined; }> => {
    if (!account) {
      // @ts-ignore
      return;
    }
    const vaultRegisteredPayload: Types.ViewRequest = {
      function: `${env.devnet.contractAddress}::delegate::is_vault_registered`,
      type_arguments: [],
      arguments: [account!.address],
    };

    console.log(vaultRegisteredPayload);
    const vaultRegisteredPromise = client.view(vaultRegisteredPayload as Types.ViewRequest);

    const delegateRegisteredPayload: Types.ViewRequest = {
      function: `${env.devnet.contractAddress}::delegate::is_delegate_registered`,
      type_arguments: [],
      arguments: [account!.address],
    }

    const delegateRegisteredPromise = await client.view(delegateRegisteredPayload as Types.ViewRequest);
    const [vaultRegisteredResult, delegateRegisteredResult] = await Promise.all([vaultRegisteredPromise, delegateRegisteredPromise]);

    return {
      currentVault: vaultRegisteredResult[0] as boolean,
      currentDelegate: delegateRegisteredResult[0] as boolean,
    };
  }

  async function submitToRegistry(): Promise<void> {
    console.log('toSubmitDelegate', toSubmitDelegate);
    console.log('toSubmitVault', toSubmitVault);
    if (toSubmitDelegate) {
      let payload: Types.TransactionPayload = {
        type: 'entry_function_payload',
        function: `${env.devnet.contractAddress}::delegate::register_delegate`,
        type_arguments: [],
        arguments: []
      }
      try {
        const tx = await signAndSubmitTransaction(payload);
        console.log(tx);
        toast.success(
          `Submitted to Delegate Registry successfully. Transaction hash - ${tx.hash}
        `)
      } catch (err) {
        console.log(err);
        toast.error('Failed to submit to Delegate Registry');
      }
    }
    if (toSubmitVault) {
      let payload: Types.TransactionPayload = {
        type: 'entry_function_payload',
        function: `${env.devnet.contractAddress}::delegate::register_vault`,
        type_arguments: [],
        arguments: []
      }
      try {
        const tx = await signAndSubmitTransaction(payload);
        console.log(tx);
        toast.success(`Submitted to Vault Registry successfully. Transaction Hash - ${tx.hash}`)
      } catch (err) {
        console.log(err);
        toast.error('Failed to submit to Vault Registry');
      }
    }
  }


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
      <table className="w-full text-left">
        <thead className="bg-white">
        <tr>
          <th scope="col" className="relative isolate py-3.5 pr-3 text-left text-lg font-semibold text-gray-900">
            Registry
            <div className="absolute inset-y-0 right-full -z-10 w-screen border-b border-b-gray-200" />
            <div className="absolute inset-y-0 left-0 -z-10 w-screen border-b border-b-gray-200" />
          </th>
          <th
            scope="col"
            className="hidden px-3 py-3.5 text-left text-lg font-semibold text-gray-900 sm:table-cell"
          >
            Status
          </th>
          <th
            scope="col"
            className="hidden px-3 py-3.5 text-left text-lg font-semibold text-gray-900 md:table-cell"
          >
            Enable
          </th>
        </tr>
        </thead>
        <tbody>
        {account && registrationDetail.map((regType) => (
          <tr key={regType.name}>
            <td className="relative py-4 pr-3 text-sm font-medium text-gray-900">
              {regType.name}
              <div className="absolute bottom-0 right-full h-px w-screen bg-gray-100" />
              <div className="absolute bottom-0 left-0 h-px w-screen bg-gray-100" />
            </td>
            <td className="hidden px-3 py-4 text-sm text-gray-500 sm:table-cell">
              <input
                id={`current-${regType.id}`}
                name={`current-${regType.name}`}
                type="checkbox"
                checked={regType.current}
                disabled={true}
                style={{ opacity: "0.5" }}
                className="h-4 w-4 rounded border-gray-300 text-indigo-600 focus:ring-indigo-600"
              />
            </td>
            <td className="hidden px-3 py-4 text-sm text-gray-500 sm:table-cell">
              <input
                id={`setAs-${regType.id}`}
                name={`setAs-${regType.id}`}
                type="checkbox"
                onChange={(e) => regType.name === RegistryName.VAULT ?
                    submitVault(e.target.checked) : submitDelegate(e.target.checked)
                }
                className="h-4 w-4 rounded border-gray-300 text-indigo-600 focus:ring-indigo-600"
              />
            </td>
          </tr>
        ))}
        </tbody>
      </table>
      <br />
      <div className="mt-5 sm:mt-6 text-center">
        <button
          onClick={async () => {
            console.log('toSubmitVault', toSubmitVault);
            console.log('toSubmitDelegate', toSubmitDelegate);
            await submitToRegistry();
          }}
          type="button"
          className="inline-flex w-80 justify-center rounded-md bg-indigo-600 px-3 py-2 text-sm font-semibold text-white shadow-sm hover:bg-indigo-500 focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-indigo-600"
        >
          Register
        </button>
      </div>
    </>
  )
}
