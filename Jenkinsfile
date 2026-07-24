stage('OWASP ZAP Dynamic Scan - DVWA') {
    steps {
        script {

            // Prompt user for DVWA session ID
            def phpSessId = input(
                id: 'dvwaCookie',
                message: 'Enter DVWA PHPSESSID',
                parameters: [
                    string(
                        name: 'PHPSESSID',
                        defaultValue: '',
                        description: 'Login to DVWA and copy the PHPSESSID cookie value.'
                    )
                ]
            )

            def dockerNetwork = "bridge"
            def dvwaUrl = "http://172.17.0.1:8081"

            // Build Cookie header
            def cookieHeader = "security=low; PHPSESSID=${phpSessId}"

            echo "Using Cookie: ${cookieHeader}"
            echo "Starting authenticated OWASP ZAP scan..."

            sh """
            docker run --rm \
              --network ${dockerNetwork} \
              -v \$(pwd):/zap/wrk/:rw \
              ghcr.io/zaproxy/zaproxy:stable \
              zap-baseline.py \
              -t ${dvwaUrl} \
              -m 2 \
              -z "-config replacer.full_list(0).description=DVWA_Cookie \
                  -config replacer.full_list(0).enabled=true \
                  -config replacer.full_list(0).matchtype=REQ_HEADER \
                  -config replacer.full_list(0).header=Cookie \
                  -config replacer.full_list(0).replacement=\\"${cookieHeader}\\"" \
              -r zap_dvwa_report.html \
              -I || true
            """
        }
    }

    post {
        always {
            archiveArtifacts artifacts: 'zap_dvwa_report.html', allowEmptyArchive: true
        }
    }
}
