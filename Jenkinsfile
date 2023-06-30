pipeline {
    agent any
    environment {
	netboxtoken = credentials('netboxtoken')
	tokenpywire = credentials('tokenpywire')
    }
    stages {
        stage('Intsall Packages') {
            steps {
		echo "Intsall Packages"
            }
        }
        stage('Test') {
            steps {
                echo 'testing'
                bat 'python jenkins.py $netboxtoken $tokenpywire'

            }
        }
    }
}
