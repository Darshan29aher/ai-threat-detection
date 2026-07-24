pipeline {
    agent any

    environment {
        SONAR_SCANNER_HOME = tool 'SonarScanner'
        TARGET_DIR = '/home/iacsd/ai-threat-detection'
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
                        -Dsonar.sources=app.py,templates \
                        -Dsonar.host.url=http://127.0.0.1:9000
                    """
                }
            }
        }

        stage('Trivy Image Scan') {
            steps {
                echo 'Scanning Flask app image and generating JSON report...'
                sh 'trivy image --format json -o trivy-report.json secure-flask-app:latest || true'
            }
            post {
                always {
                    archiveArtifacts artifacts: 'trivy-report.json', allowEmptyArchive: true
                }
            }
        }

        stage('OWASP ZAP Dynamic Scan - DVWA') {
            steps {
                script {
                    def dockerNetwork = "bridge"
                    def dvwaUrl = "http://172.17.0.1:8081" 

                    echo "Starting OWASP ZAP scan against DVWA at ${dvwaUrl}..."

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
            post {
                always {
                    archiveArtifacts artifacts: 'zap_dvwa_report.html', allowEmptyArchive: true
                }
            }
        }
    }

    post {
        always {
            echo "Automating report backup to ${TARGET_DIR}..."
            sh """
                mkdir -p ${TARGET_DIR}
                cp -f trivy-report.json ${TARGET_DIR}/ 2>/dev/null || true
                cp -f zap_dvwa_report.html ${TARGET_DIR}/ 2>/dev/null || true
            """
        }
    }
}
