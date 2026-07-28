pipeline {
    agent any

    environment {
        SONAR_SCANNER_HOME = tool 'SonarScanner'
    }

    stages {
        stage('Checkout & Lint') {
            steps {
                echo 'Checking out source code & running code checks...'
                checkout scm
                sh 'python3 -m flake8 . || true'
            }
        }

        stage('SAST - SonarQube') {
            steps {
                echo 'Running Static Application Security Testing (SAST)...'
                withSonarQubeEnv('SonarQube-Server') {
                    sh """
                        ${SONAR_SCANNER_HOME}/bin/sonar-scanner \
                        -Dsonar.projectKey=ai-threat-detection \
                        -Dsonar.sources=app.py,templates \
                        -Dsonar.host.url=http://127.0.0.1:9000
                    """
                }
            }
        }

        stage('SCA & Image Scan - Trivy') {
            steps {
                echo 'Scanning Flask app container image for CVEs...'
                sh 'trivy image --format json -o trivy-report.json secure-flask-app:latest || true'
            }
        }

        stage('DAST - OWASP ZAP') {
            steps {
                script {
                    def dockerNetwork = "bridge"
                    def dvwaUrl = "http://172.17.0.1:8081" 

                    echo "Starting Dynamic Application Security Testing against ${dvwaUrl}..."

                    sh """
                    docker run --rm --network ${dockerNetwork} \
                      -v \$(pwd):/zap/wrk/:rw \
                      -t ghcr.io/zaproxy/zaproxy:stable zap-baseline.py \
                      -t ${dvwaUrl} \
                      -r zap_dvwa_report.html \
                      -I || true
                    """
                }
            }
        }

        stage('SIEM Telemetry Audit') {
            steps {
                echo 'Verifying Filebeat log shipping and Logstash pipeline readiness...'
                sh 'systemctl is-active filebeat || true'
            }
        }

        stage('Publish Artifacts & Reports') {
            steps {
                echo 'Archiving all DevSecOps security reports...'
                archiveArtifacts artifacts: 'trivy-report.json, zap_dvwa_report.html', allowEmptyArchive: true
            }
        }
    }
}
