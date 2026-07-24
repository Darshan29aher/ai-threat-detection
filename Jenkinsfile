pipeline {
    agent any

    environment {
        SONAR_SCANNER_HOME = tool 'SonarScanner'
    }

    stages {
        stage('Checkout Code') {
            steps {
                echo 'Checking out source code...'
                checkout scm
            }
        }

        stage('SonarQube Code Analysis') {
            steps {
                withSonarQubeEnv('SonarQube-Server') {
                    sh """
                        ${SONAR_SCANNER_HOME}/bin/sonar-scanner \
                        -Dsonar.projectKey=ai-threat-detection \
                        -Dsonar.sources=. \
                        -Dsonar.host.url=http://127.0.0.1:9000
                    """
                }
            }
        }

        stage('Trivy Image Scan') {
            steps {
                echo 'Scanning Flask app image for vulnerabilities...'
                sh 'trivy image secure-flask-app:latest || true'
            }
        }

        stage('OWASP ZAP Dynamic Scan - DVWA') {
            steps {
                script {
                    // Jenkins will show a prompt in the build UI asking for your session cookie
                    def phpSessId = input(
                        id: 'dvwaCookie', 
                        message: 'Enter DVWA Session Cookie', 
                        parameters: [
                            string(
                                name: 'PHPSESSID', 
                                defaultValue: '', 
                                description: 'Log into DVWA in browser, open F12 -> Application/Storage -> Cookies, and paste your PHPSESSID value here.'
                            )
                        ]
                    )

                    def dockerNetwork = "bridge"
                    def dvwaUrl = "http://172.17.0.1:8081"
                    def cookieHeader = phpSessId ? "security=low; PHPSESSID=${phpSessId}" : "security=low"

                    echo "Starting OWASP ZAP scan against DVWA at ${dvwaUrl}..."

                    sh """
                    docker run --rm --network ${dockerNetwork} \
                      -v \$(pwd):/zap/wrk/:rw \
                      -t ghcr.io/zaproxy/zaproxy:stable zap-baseline.py \
                      -t ${dvwaUrl} \
                      -m 2 \
                      -z "-config replacer.full_list(0).description=Cookie -config replacer.full_list(0).enabled=true -config replacer.full_list(0).matchtype=REQ_HEADER -config replacer.full_list(0).header=Cookie -config replacer.full_list(0).replacement='${cookieHeader}'" \
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
    } // Closes stages
}     // Closes pipeline
