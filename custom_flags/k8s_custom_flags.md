# Kubernetes-Specific Custom Flags

## Flag: Execution of `debugfs` in a Privileged Container (VERIFY)
- **Target Objects**: Containers
- **Query**: Identify if the `debugfs` binary is executed within a container that has `container.privileged = true`.
- **Next Steps**: Implement detection for `debugfs` execution in privileged containers. Investigate the actions performed by `debugfs` and evaluate if any unauthorized file system manipulation occurred. Ensure that privileged containers are restricted in environments where elevated permissions are unnecessary.
- **Key Concepts**:  
  - **Privileged Containers**: Containers with the ability to interact with host system resources more freely, posing potential security risks. Attackers may exploit privileged containers to interact with the host file system or attempt to escape the container.
  - **debugfs**: A low-level file system debugger often used for troubleshooting. In the wrong hands, it can be used to inspect or modify file systems, potentially enabling unauthorized access or host manipulation.

---

## Flag: Suspicious CronJob Schedule
- **Target Objects**: CronJobs
- **Query**: Detect CronJobs scheduled to run unusually frequently (e.g., with `schedule = "* * * * *"` indicating execution every minute).
- **Flag**: Overly frequent CronJobs may suggest misconfigurations or malicious activity, such as resource exhaustion or continuous task execution for purposes like cryptomining.
- **Next Steps**:  
  1. Review the CronJob's schedule and purpose. 
  2. Validate if the frequent execution is justified for the workload or if it can be adjusted to a more reasonable frequency.  
  3. If suspicious, investigate the CronJob’s origin, its impact on resource usage, and potential malicious intent.
- **Key Concepts**:  
  - **CronJobs**: Kubernetes objects used to run tasks at specified intervals. Malicious actors may schedule frequent jobs to overload resources or persistently execute unwanted tasks.

---

## Flag: Unauthorized Access to Kubernetes Secrets or Kubeconfig
- **Target Objects**: Processes
- **Query**: Monitor for unauthorized access or modification of Kubernetes secrets or kubeconfig files (`~/.kube/config`).
- **Flag**: Any unexpected process or user accessing or modifying Kubernetes secrets or the kubeconfig file should be flagged for potential credential exposure or privilege escalation.
- **Next Steps**:  
  1. Investigate the process accessing the secret or kubeconfig.  
  2. Validate the legitimacy of the access attempt.  
  3. If unauthorized, revoke access, rotate credentials, and audit other sensitive files for possible tampering.
- **Key Concepts**:  
  - **Kubernetes Secrets**: Sensitive data stored in Kubernetes, often used to manage access credentials or tokens for services.  
  - **Kubeconfig**: A configuration file used to access and manage Kubernetes clusters. Unauthorized access to this file can compromise cluster security.

---

## Flag: Unapproved Container Images
- **Target Objects**: Containers
- **Query**: Detect containers using images pulled from unauthorized or unknown container registries, especially public registries that do not enforce strict validation or security checks.
- **Flag**: Containers running images from unapproved or untrusted sources should be flagged for security review, as they may introduce vulnerabilities, malware, or backdoors into the environment.
- **Next Steps**:  
  1. Investigate the source of the container image and ensure it originates from a trusted, secure registry.  
  2. Validate the image integrity by checking image signatures, ensuring no tampering or corruption.  
  3. Establish or enforce policies to restrict containers to pull images only from trusted, secure, and vetted registries. Favor registries that scan images for vulnerabilities and adhere to compliance standards.
- **Key Concepts**:  
  - **Container Registries**: Repositories where container images are stored and distributed. Public registries may pose security risks if they allow unverified images.  
  - **Image Integrity**: Critical for preventing supply chain attacks, image validation ensures that the images used are secure, free of malicious content, and have not been altered.  
  - **Trusted Registries**: Private or approved registries that enforce security measures, such as image scanning, signature validation, and version tracking, to protect against threats and vulnerabilities.


---

## Flag: Deployment with High Replica Count 
- **Target Objects**: ReplicaSet or StatefulSet
- **Query**: Identify ReplicaSets or StatefulSets where the replica count exceeds a specified threshold (e.g., more than 10 replicas).
- **Flag**: Deployments with an unusually high number of replicas may indicate improper scaling, inefficient resource usage, or even a misconfiguration that could lead to performance degradation.
- **Next Steps**:  
  1. Investigate the deployment to ensure the high replica count is intentional and necessary.  
  2. Review scaling policies and adjust if needed to optimize resource utilization.  
  3. Consider adjusting the replica count to an appropriate level based on traffic, workload needs, and infrastructure capacity.
- **Key Concepts**:  
  - **ReplicaSet**: A Kubernetes controller that ensures a specified number of pod replicas are running at all times.  
  - **StatefulSet**: A Kubernetes controller for managing stateful applications, where each replica has a stable identity.  
  - **High Replica Count**: May signal issues such as overprovisioning, unexpected traffic, or improper scaling rules, which could degrade system performance.
