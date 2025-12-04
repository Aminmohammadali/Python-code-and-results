In our scheme, we consider three entities: the TA, TC, and AS. In the implementation, the TA runs the key generator and produces the public and secret keys for both the AS and the TC. Once the TA generates the public parameters, they are uploaded to the key-load module so that all entities can retrieve them. Therefore, all public and private keys are unique and remain unchanged unless the TA re-runs the key-generation process to produce new parameters.

Whenever a vehicle requires its secret parameters, it sends a request to the TA, and the TA provides the tuple $(A_i, x_i, y_i)$. After receiving these values, the vehicle can generate endorsements for the messages it receives from the RSU. The user runs the signer code with its secret and public parameters to produce a signature using \texttt{signer.py}, and then sends the result to the verifier (in this case, the RSU). The RSU or any other entity can verify the endorsement using \texttt{verifier.py}.

To evaluate attacks and simulate a dynamic environment, we model a realistic scenario in which each RSU receives a large number of endorsements from vehicles. For this purpose, we designed the signer module to generate many signatures based on the required threshold. Note that in this model, Sybil-attack detection is deactivated so that the verifier does not perform Sybil checking. Sybil detection is enabled only in the dedicated Sybil-attack scenario.

Furthermore, we show that our scheme is resistant to replay  and unforgeability attacks. In the dynamic-environment experiment, we introduce delay and jitter using CMD commands to emulate network conditions and examine their effects on message transmission between vehicles and RSUs.

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
  

Verifier CMD code: python3 /home/mmobarak/Downloads/verifier_final.py --host 0.0.0.0  --port 5000   --disable-sybil

Verifier CMD code for sybil attack check: python3 /home/mmobarak/Downloads/verifier_final.py --host 0.0.0.0  --port 5000

Signer CMD code: /home/pi/projects/bplib_test/.venv/bin/python   /home/pi/Downloads/signer_pi_batch_parallel.py   --host 192.168.2.2   --port 5000   --message "1212122423||Alice"   --count 1   --runs 10

Signer CMD code with delay and jiter: /home/pi/projects/bplib_test/.venv/bin/python   /home/pi/Downloads/signer_pi_batch_parallel_delayandjiter.py   --host 192.168.2.2   --port 5000   --message "1212122423||Alice"   --count 10   --runs 1000   --delay-mu 20   --delay-sigma 10   --output results_mu20_sigma10.json